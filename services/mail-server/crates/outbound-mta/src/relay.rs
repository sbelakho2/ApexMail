//! The idempotent submission contract and delivery orchestration.
//!
//! # Submission
//!
//! [`Relay::submit`] takes a [`SubmitRequest`] (stable `send_unit`, recipient
//! set, message bytes, optional requested source IP) and returns an
//! [`AcceptanceRecord`] **only after the recipient server replied 250 to the
//! end of DATA**. Connection success, EHLO, MAIL FROM and RCPT acceptance are
//! never recorded as acceptance.
//!
//! Idempotency is anchored on the durable ledger's primary key:
//!
//! * a repeated `send_unit` whose row is `accepted` returns the STORED
//!   record — no second delivery (the acceptance record is the contract);
//! * a repeated `send_unit` while an attempt is in flight returns
//!   [`RelayError::InFlight`];
//! * a repeated `send_unit` while a retry is queued returns
//!   [`RelayError::AlreadyQueued`] — retries belong to the queue processor,
//!   never to a duplicate submit call;
//! * a repeated `send_unit` after a permanent failure returns
//!   [`RelayError::Permanent`]; a terminal failure is never silently retried.
//!
//! The message is stored (with an envelope and retry schedule) in
//! `outbound_relay_ledger`, so the daemon can retry it after a restart
//! without the worker resubmitting.
//!
//! # Delivery
//!
//! Recipients are grouped by domain; each domain's MX targets are walked in
//! preference order. Per target: connect (bound to the requested source IP
//! when present), EHLO, TLS per policy, MAIL FROM, RCPT, DATA. The failure
//! taxonomy lives in [`crate::retry`]:
//!
//! * connection/timeout/4xx → transient, try the next MX, then backoff;
//! * 5xx at RCPT → that recipient permanently fails;
//! * 5xx at MAIL FROM / after DATA → the whole message permanently fails;
//! * source-IP or TLS-required refusals happen BEFORE DATA.
//!
//! A permanent failure generates an RFC 3464 DSN back to the original
//! envelope sender and queues it as a new submission with a null return path
//! (never for a message that itself had a null return path). Once ANY
//! recipient has accepted the message the unit is pinned `accepted` and is
//! never retried, so deferred recipients cannot cause a duplicate delivery.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dsn::{DsnAction, DsnGenerator, DsnInputs};
use crate::ledger::{
    ClaimOutcome, LedgerError, LedgerStats, NewSubmission, QueuedSubmission, RelayLedger,
};
use crate::mx::{MxResolver, MxTarget};
use crate::response::{classify, ReplyDisposition, SmtpReply, SmtpStage};
use crate::retry::{AttemptStage, DeliveryFailure, RetryPolicy};
use crate::smtp::{SmtpClient, SmtpError, SmtpTimeouts};
use crate::source_ip::SourceIpError;
use crate::tls::TlsPolicy;

/// Relay configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// HELO/EHLO name presented to recipient servers.
    pub helo_domain: String,
    /// `Reporting-MTA` identity used in DSNs.
    pub reporting_mta: String,
    pub timeouts: SmtpTimeouts,
    pub retry: RetryPolicy,
    /// Lease held by one delivery attempt; a crashed process is reclaimed
    /// after this window.
    pub lease: Duration,
    pub max_recipients: usize,
    pub max_message_bytes: usize,
    /// Operator override for the TLS policy; `None` derives it from the
    /// destination port (25 opportunistic, 465 implicit, 587/2525 required).
    pub tls_policy_override: Option<TlsPolicy>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            helo_domain: "relay.apexmail.ee".to_string(),
            reporting_mta: "relay.apexmail.ee".to_string(),
            timeouts: SmtpTimeouts::default(),
            retry: RetryPolicy::default(),
            lease: Duration::from_secs(15 * 60),
            max_recipients: 100,
            max_message_bytes: 50 * 1024 * 1024,
            tls_policy_override: None,
        }
    }
}

/// One submission: the payload contract the worker (or the SMTP submission
/// listener that parses `X-ApexMail-Route`) hands to the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitRequest {
    /// Stable logical send unit; the idempotency key.
    pub send_unit: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub queue_id: Option<Uuid>,
    /// Envelope sender. `None` or blank = null reverse path (`MAIL FROM:<>`).
    /// A null-return-path message never produces a DSN.
    #[serde(default)]
    pub envelope_from: Option<String>,
    pub recipients: Vec<String>,
    /// Raw RFC 5322 message bytes (envelope headers included). Any reserved
    /// `X-ApexMail-*` header is stripped before delivery.
    #[serde(default)]
    pub message: Vec<u8>,
    /// Dedicated source IP the recipient-facing socket must bind.
    #[serde(default)]
    pub requested_source_ip: Option<IpAddr>,
}

/// Per-recipient outcome recorded in the acceptance record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientOutcome {
    /// The recipient server accepted the message (post-DATA 250).
    Accepted,
    /// The recipient server permanently rejected this recipient.
    Rejected,
    /// This recipient was deferred (4xx) during an attempt whose other
    /// recipients were accepted; intentionally NOT retried (a retry would
    /// duplicate the accepted copy).
    Deferred,
}

/// One recipient's result in an [`AcceptanceRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientResult {
    pub recipient: String,
    pub outcome: RecipientOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enhanced_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mx: Option<String>,
    pub tls_used: bool,
}

impl RecipientResult {
    fn from_reply(
        recipient: &str,
        outcome: RecipientOutcome,
        reply: &SmtpReply,
        mx: &str,
        tls_used: bool,
    ) -> Self {
        Self {
            recipient: recipient.to_string(),
            outcome,
            reply_code: Some(reply.code),
            enhanced_status: reply.enhanced.map(|code| code.to_string()),
            diagnostic: Some(reply.diagnostic()),
            mx: Some(mx.to_string()),
            tls_used,
        }
    }

    fn from_failure(recipient: &str, failure: &DeliveryFailure) -> Self {
        Self {
            recipient: recipient.to_string(),
            outcome: RecipientOutcome::Rejected,
            reply_code: None,
            enhanced_status: None,
            diagnostic: Some(failure.summary()),
            mx: failure.mx().map(str::to_string),
            tls_used: false,
        }
    }
}

/// The durable acceptance record. Written ONLY after a post-DATA 250.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceRecord {
    pub send_unit: String,
    /// Always `"accepted"` (kept explicit for forward-compatible readers).
    pub state: String,
    pub accepted_at: DateTime<Utc>,
    pub attempt: u32,
    /// The MX that accepted the message.
    #[serde(default)]
    pub remote_mx: Option<String>,
    /// Whether the accepted connection used TLS.
    pub tls_used: bool,
    /// What the submission requested.
    #[serde(default)]
    pub requested_source_ip: Option<IpAddr>,
    /// What the kernel bound and this relay verified. The worker compares
    /// this with the requested IP; a mismatch is an audit anomaly, never a
    /// retry signal.
    #[serde(default)]
    pub actual_source_ip: Option<IpAddr>,
    pub recipients: Vec<RecipientResult>,
    /// Ledger keys of DSNs enqueued for permanent recipient failures.
    #[serde(default)]
    pub dsn_send_units: Vec<String>,
}

impl AcceptanceRecord {
    /// True only when the acceptance may consume dedicated-IP warmup
    /// capacity: a source IP was requested and the verified bound IP equals
    /// it (see [`crate::source_ip::counts_toward_warmup`]).
    pub fn warmup_capacity_consumed(&self) -> bool {
        crate::source_ip::counts_toward_warmup(self.requested_source_ip, self.actual_source_ip)
    }
}

/// Submission/delivery failure returned by [`Relay::submit`] and
/// [`Relay::process_due`].
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("invalid submission: {0}")]
    InvalidRequest(String),
    #[error(
        "submission '{send_unit}' already has a delivery attempt in flight (attempt {attempt})"
    )]
    InFlight {
        send_unit: String,
        attempt: u32,
        next_attempt_at: Option<DateTime<Utc>>,
    },
    #[error("submission '{send_unit}' is already queued for retry at {next_attempt_at}")]
    AlreadyQueued {
        send_unit: String,
        attempt: u32,
        next_attempt_at: DateTime<Utc>,
    },
    #[error(
        "submission '{send_unit}' failed transiently at attempt {attempt}; \
         next attempt at {next_attempt_at}: {reason}"
    )]
    RetryScheduled {
        send_unit: String,
        attempt: u32,
        next_attempt_at: DateTime<Utc>,
        reason: String,
    },
    #[error("submission '{send_unit}' permanently failed at attempt {attempt}: {reason}")]
    Permanent {
        send_unit: String,
        attempt: u32,
        reason: String,
        /// DSN ledger keys enqueued back to the original envelope sender.
        dsn_send_units: Vec<String>,
    },
    #[error("acceptance ledger error: {0}")]
    Ledger(#[from] LedgerError),
    #[error("delivery error: {0}")]
    Delivery(String),
}

/// Counters returned by one [`Relay::process_due`] pass.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ProcessReport {
    pub claimed: u64,
    pub accepted: u64,
    pub retry_scheduled: u64,
    pub permanently_failed: u64,
    pub errors: u64,
}

/// The recipient-facing outbound relay.
pub struct Relay {
    ledger: Arc<dyn RelayLedger>,
    resolver: Arc<dyn MxResolver>,
    config: RelayConfig,
    dsn: DsnGenerator,
}

impl Relay {
    pub fn new(
        ledger: Arc<dyn RelayLedger>,
        resolver: Arc<dyn MxResolver>,
        config: RelayConfig,
    ) -> Self {
        let dsn = DsnGenerator::new(config.reporting_mta.clone());
        Self {
            ledger,
            resolver,
            config,
            dsn,
        }
    }

    /// Submit a message. Idempotent by `send_unit` (see the module docs).
    pub async fn submit(&self, request: SubmitRequest) -> Result<AcceptanceRecord, RelayError> {
        validate_request(&request, &self.config)?;
        let message = strip_or_keep(&request.message);
        if message.is_empty() {
            return Err(RelayError::InvalidRequest(
                "message is empty after removing reserved internal headers".to_string(),
            ));
        }
        let envelope_from = request
            .envelope_from
            .as_deref()
            .map(str::trim)
            .filter(|sender| !sender.is_empty())
            .map(str::to_string);
        let new = NewSubmission {
            send_unit: request.send_unit.clone(),
            tenant_id: request.tenant_id.clone(),
            queue_id: request.queue_id,
            envelope_from,
            recipients: request.recipients.clone(),
            message,
            requested_source_ip: request.requested_source_ip,
            max_attempts: self.config.retry.max_attempts,
        };
        let now = Utc::now();
        match self
            .ledger
            .claim_submission(new, now, self.config.lease)
            .await?
        {
            ClaimOutcome::Claimed(row) => self.deliver(*row).await,
            ClaimOutcome::AlreadyAccepted(record) => Ok(record),
            ClaimOutcome::InFlight {
                attempt,
                next_attempt_at,
            } => Err(RelayError::InFlight {
                send_unit: request.send_unit,
                attempt,
                next_attempt_at,
            }),
            ClaimOutcome::AlreadyQueued {
                attempt,
                next_attempt_at,
            } => Err(RelayError::AlreadyQueued {
                send_unit: request.send_unit,
                attempt,
                next_attempt_at,
            }),
            ClaimOutcome::PermanentlyFailed {
                attempt,
                last_error,
            } => Err(RelayError::Permanent {
                send_unit: request.send_unit,
                attempt,
                reason: last_error.unwrap_or_else(|| "permanent failure".to_string()),
                dsn_send_units: Vec::new(),
            }),
        }
    }

    /// Claim and process due retries / expired leases. The daemon calls this
    /// on every poll tick.
    pub async fn process_due(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<ProcessReport, RelayError> {
        let claimed = self.ledger.claim_due(now, self.config.lease, limit).await?;
        let mut report = ProcessReport {
            claimed: claimed.len() as u64,
            ..ProcessReport::default()
        };
        for row in claimed {
            match self.deliver(row).await {
                Ok(_) => report.accepted += 1,
                Err(RelayError::RetryScheduled { .. }) => report.retry_scheduled += 1,
                Err(RelayError::Permanent { .. }) => report.permanently_failed += 1,
                Err(error) => {
                    report.errors += 1;
                    tracing::error!(error = %error, "queued delivery failed unexpectedly");
                }
            }
        }
        Ok(report)
    }

    /// Return crashed `delivering` rows to `pending`.
    pub async fn reclaim_expired(&self, now: DateTime<Utc>) -> Result<u64, RelayError> {
        let reclaimed = self.ledger.reclaim_expired(now).await?;
        if reclaimed > 0 {
            tracing::warn!(
                reclaimed,
                "reclaimed outbound deliveries whose lease expired (crashed attempts)"
            );
        }
        Ok(reclaimed)
    }

    pub async fn stats(&self) -> Result<LedgerStats, RelayError> {
        Ok(self.ledger.stats().await?)
    }

    pub async fn get(&self, send_unit: &str) -> Result<Option<QueuedSubmission>, RelayError> {
        Ok(self.ledger.get(send_unit).await?)
    }

    /// Deliver one claimed row and transition the ledger. Acceptance is
    /// recorded only for a post-DATA 250.
    async fn deliver(&self, row: QueuedSubmission) -> Result<AcceptanceRecord, RelayError> {
        let arrival = Utc::now();
        let attempt = row.attempt;
        if row.message.is_empty() {
            let reason = "queued message is empty".to_string();
            self.ledger
                .record_permanent(&row.send_unit, attempt, &reason)
                .await?;
            return Err(RelayError::Permanent {
                send_unit: row.send_unit,
                attempt,
                reason,
                dsn_send_units: Vec::new(),
            });
        }
        if row.message.len() > self.config.max_message_bytes {
            let reason = format!(
                "message of {} bytes exceeds the {}-byte limit",
                row.message.len(),
                self.config.max_message_bytes
            );
            let dsn_units = self.enqueue_message_too_large_dsns(&row, arrival).await;
            self.ledger
                .record_permanent(&row.send_unit, attempt, &reason)
                .await?;
            return Err(RelayError::Permanent {
                send_unit: row.send_unit,
                attempt,
                reason,
                dsn_send_units: dsn_units,
            });
        }

        let groups = group_recipients(&row.recipients)?;
        let mut accepted_results: Vec<RecipientResult> = Vec::new();
        let mut rejected_results: Vec<RecipientResult> = Vec::new();
        let mut deferred_results: Vec<RecipientResult> = Vec::new();
        let mut transient_failures: Vec<DeliveryFailure> = Vec::new();
        let mut permanent_failures: Vec<DeliveryFailure> = Vec::new();
        let mut remote_mx: Option<String> = None;
        let mut tls_used = false;
        let mut actual_source_ip: Option<IpAddr> = None;

        for (domain, recipients) in &groups {
            let targets = match self.resolver.resolve(domain).await {
                Ok(targets) => targets,
                Err(error) if error.is_permanent() => {
                    let failure = DeliveryFailure::DomainUndeliverable {
                        domain: domain.clone(),
                        message: error.to_string(),
                    };
                    for recipient in recipients {
                        rejected_results.push(RecipientResult::from_failure(recipient, &failure));
                    }
                    permanent_failures.push(failure);
                    continue;
                }
                Err(error) => {
                    transient_failures.push(DeliveryFailure::Transient {
                        mx: None,
                        stage: AttemptStage::Resolve,
                        message: error.to_string(),
                    });
                    continue;
                }
            };

            let mut last_transient: Option<DeliveryFailure> = None;
            let mut settled = false;
            for target in &targets {
                match self
                    .attempt_target(&row, target, recipients, &row.message)
                    .await
                {
                    TargetOutcome::Accepted {
                        mx,
                        tls_used: used,
                        actual_source_ip: bound_ip,
                        results,
                    } => {
                        remote_mx = Some(mx);
                        tls_used = used;
                        actual_source_ip = bound_ip;
                        for result in results {
                            match result.outcome {
                                RecipientOutcome::Accepted => accepted_results.push(result),
                                RecipientOutcome::Rejected => rejected_results.push(result),
                                RecipientOutcome::Deferred => deferred_results.push(result),
                            }
                        }
                        settled = true;
                        break;
                    }
                    TargetOutcome::AllRecipientsRejected {
                        mx,
                        tls_used: used,
                        actual_source_ip: bound_ip,
                        results,
                    } => {
                        remote_mx.get_or_insert(mx);
                        tls_used = used;
                        actual_source_ip = bound_ip.or(actual_source_ip);
                        rejected_results.extend(results);
                        settled = true;
                        break;
                    }
                    TargetOutcome::Permanent { failure, results } => {
                        remote_mx
                            .get_or_insert_with(|| failure.mx().unwrap_or("unknown").to_string());
                        rejected_results.extend(results);
                        permanent_failures.push(failure);
                        settled = true;
                        break;
                    }
                    TargetOutcome::Transient(failure) => {
                        last_transient = Some(failure);
                    }
                }
            }
            if !settled {
                if let Some(failure) = last_transient {
                    transient_failures.push(failure);
                }
            }
        }

        if !accepted_results.is_empty() {
            // Post-DATA 250 recorded: pin the unit accepted. Deferred
            // recipients are deliberately NOT retried — a retry would
            // duplicate the accepted copy.
            let mut dsn_send_units = Vec::new();
            for result in &rejected_results {
                if let Some(unit) = self
                    .enqueue_rejection_dsn(&row, result, &remote_mx, arrival)
                    .await
                {
                    dsn_send_units.push(unit);
                }
            }
            let mut recipients = accepted_results;
            recipients.extend(rejected_results);
            recipients.extend(deferred_results);
            let record = AcceptanceRecord {
                send_unit: row.send_unit.clone(),
                state: "accepted".to_string(),
                accepted_at: Utc::now(),
                attempt,
                remote_mx,
                tls_used,
                requested_source_ip: row.requested_source_ip,
                actual_source_ip,
                recipients,
                dsn_send_units,
            };
            self.ledger.record_accepted(&row.send_unit, &record).await?;
            tracing::info!(
                send_unit = %row.send_unit,
                mx = ?record.remote_mx,
                requested_source_ip = ?record.requested_source_ip,
                actual_source_ip = ?record.actual_source_ip,
                warmup_capacity_consumed = record.warmup_capacity_consumed(),
                "outbound message accepted after DATA"
            );
            return Ok(record);
        }

        if transient_failures.is_empty() {
            // Every failure is permanent: reject the whole send unit, DSN the
            // rejected recipients, and never retry.
            let dsn_send_units = self
                .enqueue_permanent_dsns(&row, &rejected_results, &permanent_failures, arrival)
                .await;
            let reason = summarize_failures(&permanent_failures, &rejected_results);
            self.ledger
                .record_permanent(&row.send_unit, attempt, &reason)
                .await?;
            tracing::warn!(send_unit = %row.send_unit, reason, "outbound message permanently failed");
            return Err(RelayError::Permanent {
                send_unit: row.send_unit,
                attempt,
                reason,
                dsn_send_units,
            });
        }

        // Transient failure: retry with backoff, bounded by max_attempts.
        let now = Utc::now();
        match self.config.retry.next_attempt_at(attempt, now) {
            Some(next_attempt_at) => {
                let reason = summarize_failures(&transient_failures, &rejected_results);
                self.ledger
                    .record_retry(&row.send_unit, attempt, next_attempt_at, &reason)
                    .await?;
                tracing::warn!(
                    send_unit = %row.send_unit,
                    attempt,
                    %next_attempt_at,
                    reason,
                    "outbound delivery deferred; retry scheduled"
                );
                Err(RelayError::RetryScheduled {
                    send_unit: row.send_unit,
                    attempt,
                    next_attempt_at,
                    reason,
                })
            }
            None => {
                // Ceiling reached: dead-letter with a delivery-expired DSN
                // (RFC 3463 4.4.7) unless the return path is null.
                let reason = format!(
                    "retry ceiling reached after {attempt} attempts; last failure: {}",
                    summarize_failures(&transient_failures, &rejected_results)
                );
                let dsn_send_units = self.enqueue_expired_dsns(&row, arrival).await;
                self.ledger
                    .record_permanent(&row.send_unit, attempt, &reason)
                    .await?;
                Err(RelayError::Permanent {
                    send_unit: row.send_unit,
                    attempt,
                    reason,
                    dsn_send_units,
                })
            }
        }
    }

    fn policy_for_port(&self, port: u16) -> TlsPolicy {
        self.config
            .tls_policy_override
            .unwrap_or_else(|| TlsPolicy::for_port(port))
    }

    /// One delivery attempt against one MX target (all its addresses).
    async fn attempt_target(
        &self,
        row: &QueuedSubmission,
        target: &MxTarget,
        recipients: &[String],
        message: &[u8],
    ) -> TargetOutcome {
        let mut last_transient: Option<DeliveryFailure> = None;
        for address in &target.addresses {
            let policy = self.policy_for_port(address.port());
            let mut session = match SmtpClient::connect(
                *address,
                &target.exchange,
                row.requested_source_ip,
                policy,
                self.config.timeouts,
            )
            .await
            {
                Ok(session) => session,
                Err(error) => {
                    last_transient = Some(self.connect_failure(&target.exchange, error));
                    continue;
                }
            };
            let mut actual_source_ip = session.actual_source_ip();

            if let Err(error) = session.ehlo(&self.config.helo_domain).await {
                last_transient = Some(self.ehlo_failure(&target.exchange, error));
                session.quit().await;
                continue;
            }
            let capabilities = session.capabilities().clone();

            // ── TLS policy ───────────────────────────────────────────────
            let mut tls_used = policy == TlsPolicy::ImplicitTlsRequired;
            match policy {
                TlsPolicy::ImplicitTlsRequired => {}
                TlsPolicy::StartTlsRequired => {
                    if !capabilities.starttls {
                        last_transient = Some(DeliveryFailure::TlsRequiredUnavailable {
                            mx: target.exchange.clone(),
                            message: format!("{address} did not advertise STARTTLS"),
                        });
                        session.quit().await;
                        continue;
                    }
                    match session.starttls(&target.exchange).await {
                        Ok(upgraded) => {
                            session = upgraded;
                            actual_source_ip = session.actual_source_ip();
                            tls_used = true;
                        }
                        Err(error) => {
                            last_transient = Some(DeliveryFailure::TlsRequiredUnavailable {
                                mx: target.exchange.clone(),
                                message: format!("STARTTLS handshake failed: {error}"),
                            });
                            continue;
                        }
                    }
                }
                TlsPolicy::Opportunistic => {
                    if capabilities.starttls {
                        match session.starttls(&target.exchange).await {
                            Ok(upgraded) => {
                                session = upgraded;
                                actual_source_ip = session.actual_source_ip();
                                tls_used = true;
                            }
                            Err(error) => {
                                // Advertised but failed: never downgrade to
                                // cleartext mid-session; try the next MX.
                                last_transient = Some(DeliveryFailure::Transient {
                                    mx: Some(target.exchange.clone()),
                                    stage: AttemptStage::StartTls,
                                    message: format!("STARTTLS handshake failed: {error}"),
                                });
                                continue;
                            }
                        }
                    } else {
                        tracing::warn!(
                            mx = %target.exchange,
                            address = %address,
                            "peer did not advertise STARTTLS; opportunistic policy continues in cleartext (tls_used=false)"
                        );
                    }
                }
            }

            // ── MAIL FROM ────────────────────────────────────────────────
            let mail_reply = match session.mail_from(row.envelope_from.as_deref()).await {
                Ok(reply) => reply,
                Err(error) => {
                    last_transient =
                        Some(self.smtp_failure(&target.exchange, AttemptStage::MailFrom, error));
                    session.quit().await;
                    continue;
                }
            };
            match classify(SmtpStage::MailFrom, &mail_reply) {
                ReplyDisposition::Accepted => {}
                ReplyDisposition::Transient => {
                    last_transient = Some(DeliveryFailure::Transient {
                        mx: Some(target.exchange.clone()),
                        stage: AttemptStage::MailFrom,
                        message: mail_reply.diagnostic(),
                    });
                    session.quit().await;
                    continue;
                }
                _ => {
                    let failure = DeliveryFailure::MessageRejected {
                        mx: target.exchange.clone(),
                        reply: mail_reply.clone(),
                    };
                    let results = reply_results(
                        recipients,
                        &mail_reply,
                        RecipientOutcome::Rejected,
                        &target.exchange,
                        tls_used,
                    );
                    session.quit().await;
                    return TargetOutcome::Permanent { failure, results };
                }
            }

            // ── RCPT TO ──────────────────────────────────────────────────
            let mut accepted: Vec<RecipientResult> = Vec::new();
            let mut rejected: Vec<RecipientResult> = Vec::new();
            let mut deferred: Vec<RecipientResult> = Vec::new();
            let mut rcpt_aborted = false;
            for recipient in recipients {
                let reply = match session.rcpt_to(recipient).await {
                    Ok(reply) => reply,
                    Err(error) => {
                        last_transient =
                            Some(self.smtp_failure(&target.exchange, AttemptStage::RcptTo, error));
                        rcpt_aborted = true;
                        break;
                    }
                };
                match classify(SmtpStage::RcptTo, &reply) {
                    ReplyDisposition::Accepted => accepted.push(RecipientResult::from_reply(
                        recipient,
                        RecipientOutcome::Accepted,
                        &reply,
                        &target.exchange,
                        tls_used,
                    )),
                    ReplyDisposition::PermanentRecipient => {
                        rejected.push(RecipientResult::from_reply(
                            recipient,
                            RecipientOutcome::Rejected,
                            &reply,
                            &target.exchange,
                            tls_used,
                        ))
                    }
                    ReplyDisposition::Transient => deferred.push(RecipientResult::from_reply(
                        recipient,
                        RecipientOutcome::Deferred,
                        &reply,
                        &target.exchange,
                        tls_used,
                    )),
                    _ => deferred.push(RecipientResult::from_reply(
                        recipient,
                        RecipientOutcome::Deferred,
                        &reply,
                        &target.exchange,
                        tls_used,
                    )),
                }
            }
            if rcpt_aborted && accepted.is_empty() {
                session.quit().await;
                continue;
            }
            if accepted.is_empty() {
                if !rejected.is_empty() && deferred.is_empty() {
                    session.quit().await;
                    return TargetOutcome::AllRecipientsRejected {
                        mx: target.exchange.clone(),
                        tls_used,
                        actual_source_ip,
                        results: rejected,
                    };
                }
                let deferred_detail = deferred
                    .iter()
                    .filter_map(|result| result.diagnostic.clone())
                    .collect::<Vec<_>>()
                    .join("; ");
                let detail = if deferred_detail.is_empty() {
                    format!("{} deferred, {} rejected", deferred.len(), rejected.len())
                } else {
                    deferred_detail
                };
                last_transient = Some(DeliveryFailure::Transient {
                    mx: Some(target.exchange.clone()),
                    stage: AttemptStage::RcptTo,
                    message: format!("no recipient accepted: {detail}"),
                });
                session.quit().await;
                continue;
            }

            // ── DATA ─────────────────────────────────────────────────────
            let data_reply = match session.data(message).await {
                Ok(reply) => reply,
                Err(error) => {
                    last_transient =
                        Some(self.smtp_failure(&target.exchange, AttemptStage::EndOfData, error));
                    session.quit().await;
                    continue;
                }
            };
            match classify(SmtpStage::EndOfData, &data_reply) {
                ReplyDisposition::Accepted => {
                    let mut results = accepted;
                    results.extend(rejected);
                    results.extend(deferred);
                    session.quit().await;
                    return TargetOutcome::Accepted {
                        mx: target.exchange.clone(),
                        tls_used,
                        actual_source_ip,
                        results,
                    };
                }
                ReplyDisposition::Transient => {
                    last_transient = Some(DeliveryFailure::Transient {
                        mx: Some(target.exchange.clone()),
                        stage: AttemptStage::EndOfData,
                        message: data_reply.diagnostic(),
                    });
                    session.quit().await;
                    continue;
                }
                _ => {
                    let failure = DeliveryFailure::MessageRejected {
                        mx: target.exchange.clone(),
                        reply: data_reply.clone(),
                    };
                    let results = reply_results(
                        recipients,
                        &data_reply,
                        RecipientOutcome::Rejected,
                        &target.exchange,
                        tls_used,
                    );
                    session.quit().await;
                    return TargetOutcome::Permanent { failure, results };
                }
            }
        }

        TargetOutcome::Transient(
            last_transient.unwrap_or_else(|| DeliveryFailure::Transient {
                mx: Some(target.exchange.clone()),
                stage: AttemptStage::Connect,
                message: "no address of this MX target could be attempted".to_string(),
            }),
        )
    }

    fn connect_failure(&self, mx: &str, error: SmtpError) -> DeliveryFailure {
        match error {
            SmtpError::Connect(crate::source_ip::ConnectError::SourceIp(source_error)) => {
                match source_ip_of_error(&source_error) {
                    Some(requested) => DeliveryFailure::SourceIpUnverified {
                        requested,
                        message: source_error.to_string(),
                    },
                    None => DeliveryFailure::Transient {
                        mx: Some(mx.to_string()),
                        stage: AttemptStage::Connect,
                        message: source_error.to_string(),
                    },
                }
            }
            other => DeliveryFailure::Transient {
                mx: Some(mx.to_string()),
                stage: AttemptStage::Connect,
                message: other.to_string(),
            },
        }
    }

    fn ehlo_failure(&self, mx: &str, error: SmtpError) -> DeliveryFailure {
        if let Some((_, reply)) = error.reply() {
            if reply.is_permanent() {
                return DeliveryFailure::AllMxRefused {
                    message: format!("{mx} refused EHLO/HELO: {}", reply.diagnostic()),
                };
            }
        }
        DeliveryFailure::Transient {
            mx: Some(mx.to_string()),
            stage: AttemptStage::Ehlo,
            message: error.to_string(),
        }
    }

    fn smtp_failure(&self, mx: &str, stage: AttemptStage, error: SmtpError) -> DeliveryFailure {
        if let Some((reply_stage, reply)) = error.reply() {
            if reply.is_permanent() {
                return match classify(reply_stage, reply) {
                    ReplyDisposition::PermanentRecipient => DeliveryFailure::Transient {
                        // A permanent-recipient reply outside RCPT is not a
                        // per-recipient verdict; treat it as this MX refusing.
                        mx: Some(mx.to_string()),
                        stage,
                        message: reply.diagnostic(),
                    },
                    _ => DeliveryFailure::AllMxRefused {
                        message: format!(
                            "{mx} refused during {}: {}",
                            stage.as_str(),
                            reply.diagnostic()
                        ),
                    },
                };
            }
        }
        DeliveryFailure::Transient {
            mx: Some(mx.to_string()),
            stage,
            message: error.to_string(),
        }
    }

    /// Queue the DSN for one permanently rejected recipient (no-op for a null
    /// return path).
    async fn enqueue_rejection_dsn(
        &self,
        row: &QueuedSubmission,
        result: &RecipientResult,
        remote_mx: &Option<String>,
        arrival: DateTime<Utc>,
    ) -> Option<String> {
        let inputs = DsnInputs {
            final_recipient: result.recipient.clone(),
            action: DsnAction::Failed,
            status: result
                .enhanced_status
                .clone()
                .unwrap_or_else(|| "5.0.0".to_string()),
            diagnostic_code: normalize_diagnostic(result.diagnostic.as_deref()),
            remote_mta: result.mx.clone().or_else(|| remote_mx.clone()),
            arrival_date: arrival,
            original_envelope_id: None,
        };
        self.enqueue_dsn(row, inputs, &result.recipient).await
    }

    async fn enqueue_permanent_dsns(
        &self,
        row: &QueuedSubmission,
        rejected_results: &[RecipientResult],
        permanent_failures: &[DeliveryFailure],
        arrival: DateTime<Utc>,
    ) -> Vec<String> {
        let mut units = Vec::new();
        if !rejected_results.is_empty() {
            for result in rejected_results {
                if let Some(unit) = self
                    .enqueue_rejection_dsn(row, result, &None, arrival)
                    .await
                {
                    units.push(unit);
                }
            }
        } else {
            // Whole-message failures (e.g. retry ceiling) without per-recipient
            // results: one DSN per original recipient.
            let status = permanent_failures
                .first()
                .map(failure_dsn_status)
                .unwrap_or_else(|| "5.0.0".to_string());
            let diagnostic = permanent_failures
                .first()
                .map(DeliveryFailure::summary)
                .unwrap_or_else(|| "permanent delivery failure".to_string());
            for recipient in &row.recipients {
                let inputs = DsnInputs {
                    final_recipient: recipient.clone(),
                    action: DsnAction::Failed,
                    status: status.clone(),
                    diagnostic_code: normalize_diagnostic(Some(&diagnostic)),
                    remote_mta: None,
                    arrival_date: arrival,
                    original_envelope_id: None,
                };
                if let Some(unit) = self.enqueue_dsn(row, inputs, recipient).await {
                    units.push(unit);
                }
            }
        }
        units
    }

    async fn enqueue_expired_dsns(
        &self,
        row: &QueuedSubmission,
        arrival: DateTime<Utc>,
    ) -> Vec<String> {
        let mut units = Vec::new();
        for recipient in &row.recipients {
            let inputs = DsnInputs::delivery_expired(
                recipient.clone(),
                arrival,
                "smtp; 4.4.7 delivery time expired at the relay (retry ceiling reached)"
                    .to_string(),
            );
            if let Some(unit) = self.enqueue_dsn(row, inputs, recipient).await {
                units.push(unit);
            }
        }
        units
    }

    async fn enqueue_message_too_large_dsns(
        &self,
        row: &QueuedSubmission,
        arrival: DateTime<Utc>,
    ) -> Vec<String> {
        let mut units = Vec::new();
        for recipient in &row.recipients {
            let inputs = DsnInputs {
                final_recipient: recipient.clone(),
                action: DsnAction::Failed,
                status: "5.3.4".to_string(),
                diagnostic_code: "smtp; 552 5.3.4 message too large for relay policy".to_string(),
                remote_mta: None,
                arrival_date: arrival,
                original_envelope_id: None,
            };
            if let Some(unit) = self.enqueue_dsn(row, inputs, recipient).await {
                units.push(unit);
            }
        }
        units
    }

    /// Generate and durably enqueue one DSN. Returns the DSN ledger key when
    /// a DSN was generated (including when it already existed — the unit is
    /// then already queued), `None` for a null return path or generation
    /// failure.
    async fn enqueue_dsn(
        &self,
        row: &QueuedSubmission,
        inputs: DsnInputs,
        key_tag: &str,
    ) -> Option<String> {
        let sender = row.envelope_from.as_deref()?;
        let generated = match self.dsn.generate(&inputs, Some(sender), &row.message) {
            Ok(generated) => generated,
            Err(error) => {
                tracing::warn!(
                    send_unit = %row.send_unit,
                    recipient = %inputs.final_recipient,
                    error = %error,
                    "DSN not generated"
                );
                return None;
            }
        };
        let dsn_unit = format!("{}:dsn:{}", row.send_unit, sanitize_key(key_tag));
        let new = NewSubmission {
            send_unit: dsn_unit.clone(),
            tenant_id: row.tenant_id.clone(),
            queue_id: row.queue_id,
            envelope_from: None, // DSNs are sent with MAIL FROM:<>
            recipients: vec![generated.envelope_to.clone()],
            message: generated.message,
            requested_source_ip: row.requested_source_ip,
            max_attempts: self.config.retry.max_attempts,
        };
        match self.ledger.enqueue_dsn(new, Utc::now()).await {
            Ok(_inserted) => Some(dsn_unit),
            Err(error) => {
                tracing::error!(
                    send_unit = %row.send_unit,
                    error = %error,
                    "failed to enqueue DSN on the durable ledger"
                );
                None
            }
        }
    }
}

/// Outcome of one MX target attempt.
enum TargetOutcome {
    /// The recipient server accepted the message after DATA.
    Accepted {
        mx: String,
        tls_used: bool,
        actual_source_ip: Option<IpAddr>,
        results: Vec<RecipientResult>,
    },
    /// Every recipient was permanently rejected at RCPT TO (no DATA sent).
    AllRecipientsRejected {
        mx: String,
        tls_used: bool,
        actual_source_ip: Option<IpAddr>,
        results: Vec<RecipientResult>,
    },
    /// The whole message was permanently rejected.
    Permanent {
        failure: DeliveryFailure,
        results: Vec<RecipientResult>,
    },
    /// Try the next MX target, then retry.
    Transient(DeliveryFailure),
}

fn strip_or_keep(message: &[u8]) -> Vec<u8> {
    crate::strip_internal_headers(message)
}

fn validate_request(request: &SubmitRequest, config: &RelayConfig) -> Result<(), RelayError> {
    let send_unit = request.send_unit.trim();
    if send_unit.is_empty() || send_unit.len() > 512 {
        return Err(RelayError::InvalidRequest(
            "send_unit must be a non-empty string of at most 512 characters".to_string(),
        ));
    }
    if request.recipients.is_empty() {
        return Err(RelayError::InvalidRequest(
            "at least one recipient is required".to_string(),
        ));
    }
    if request.recipients.len() > config.max_recipients {
        return Err(RelayError::InvalidRequest(format!(
            "{} recipients exceed the configured maximum of {}",
            request.recipients.len(),
            config.max_recipients
        )));
    }
    for recipient in &request.recipients {
        validate_address(recipient).map_err(|error| {
            RelayError::InvalidRequest(format!("invalid recipient '{recipient}': {error}"))
        })?;
    }
    if let Some(sender) = request
        .envelope_from
        .as_deref()
        .map(str::trim)
        .filter(|sender| !sender.is_empty())
    {
        validate_address(sender).map_err(|error| {
            RelayError::InvalidRequest(format!("invalid envelope sender '{sender}': {error}"))
        })?;
    }
    if request.message.is_empty() {
        return Err(RelayError::InvalidRequest(
            "message bytes are required".to_string(),
        ));
    }
    if request.message.len() > config.max_message_bytes {
        return Err(RelayError::InvalidRequest(format!(
            "message of {} bytes exceeds the configured maximum of {}",
            request.message.len(),
            config.max_message_bytes
        )));
    }
    Ok(())
}

fn validate_address(address: &str) -> Result<(), String> {
    if address.is_empty() || address.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("address is empty or contains whitespace/control characters".to_string());
    }
    let (local, domain) = address
        .rsplit_once('@')
        .ok_or_else(|| "address has no '@'".to_string())?;
    if local.is_empty() {
        return Err("address has an empty local part".to_string());
    }
    crate::mx::normalize_domain(domain).map_err(|error| error.to_string())?;
    Ok(())
}

fn group_recipients(recipients: &[String]) -> Result<Vec<(String, Vec<String>)>, RelayError> {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for recipient in recipients {
        let domain = recipient
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .ok_or_else(|| {
                RelayError::InvalidRequest(format!("recipient '{recipient}' has no domain"))
            })?;
        let domain = crate::mx::normalize_domain(domain).map_err(|error| {
            RelayError::InvalidRequest(format!("recipient '{recipient}': {error}"))
        })?;
        match index.get(&domain) {
            Some(position) => groups[*position].1.push(recipient.clone()),
            None => {
                index.insert(domain.clone(), groups.len());
                groups.push((domain, vec![recipient.clone()]));
            }
        }
    }
    Ok(groups)
}

fn reply_results(
    recipients: &[String],
    reply: &SmtpReply,
    outcome: RecipientOutcome,
    mx: &str,
    tls_used: bool,
) -> Vec<RecipientResult> {
    recipients
        .iter()
        .map(|recipient| RecipientResult::from_reply(recipient, outcome, reply, mx, tls_used))
        .collect()
}

fn summarize_failures(
    failures: &[DeliveryFailure],
    rejected_results: &[RecipientResult],
) -> String {
    let mut parts: Vec<String> = failures.iter().map(DeliveryFailure::summary).collect();
    if parts.is_empty() {
        for result in rejected_results {
            if let Some(diagnostic) = &result.diagnostic {
                parts.push(format!("{}: {diagnostic}", result.recipient));
            }
        }
    }
    if parts.is_empty() {
        "delivery failed".to_string()
    } else {
        parts.join("; ")
    }
}

fn failure_dsn_status(failure: &DeliveryFailure) -> String {
    match failure {
        DeliveryFailure::RecipientRejected { reply, .. }
        | DeliveryFailure::MessageRejected { reply, .. } => reply.dsn_status(),
        DeliveryFailure::DomainUndeliverable { .. } => "5.1.1".to_string(),
        DeliveryFailure::AllMxRefused { .. } => "5.4.0".to_string(),
        DeliveryFailure::RetryCeilingExhausted { .. } => "4.4.7".to_string(),
        _ => "5.0.0".to_string(),
    }
}

fn normalize_diagnostic(diagnostic: Option<&str>) -> String {
    match diagnostic {
        Some(text) if text.starts_with("smtp;") => text.to_string(),
        Some(text) => format!("smtp; {text}"),
        None => "smtp; 550 permanent delivery failure".to_string(),
    }
}

fn sanitize_key(key: &str) -> String {
    let sanitized: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':' | '+') {
                c
            } else {
                '_'
            }
        })
        .collect();
    sanitized.chars().take(200).collect()
}

fn source_ip_of_error(error: &SourceIpError) -> Option<IpAddr> {
    match error {
        SourceIpError::SocketAllocation { requested, .. }
        | SourceIpError::Bind { requested, .. }
        | SourceIpError::Unverified { requested, .. }
        | SourceIpError::FamilyMismatch { requested, .. }
        | SourceIpError::LocalAddressUnavailable { requested, .. } => Some(*requested),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::test_support::MemoryLedger;
    use crate::mx::test_support::StaticMxResolver;
    use crate::mx::MxError;
    use crate::test_smtp::{FakeSmtpConfig, FakeSmtpServer, ReplySpec, ScriptedReply};

    fn relay_config() -> RelayConfig {
        RelayConfig {
            helo_domain: "relay.test".to_string(),
            reporting_mta: "relay.test".to_string(),
            ..RelayConfig::default()
        }
    }

    fn request() -> SubmitRequest {
        SubmitRequest {
            send_unit: "email_queue:unit-1:user@example.com".to_string(),
            tenant_id: Some("tenant-1".to_string()),
            queue_id: None,
            envelope_from: Some("sender@apexmail.ee".to_string()),
            recipients: vec!["user@example.com".to_string()],
            message: b"From: sender@apexmail.ee\r\nTo: user@example.com\r\nSubject: hi\r\n\r\nbody"
                .to_vec(),
            requested_source_ip: None,
        }
    }

    struct Harness {
        relay: Relay,
        ledger: Arc<MemoryLedger>,
        server: FakeSmtpServer,
    }

    async fn harness(config: RelayConfig, server_config: FakeSmtpConfig) -> Harness {
        let server = FakeSmtpServer::start(server_config).await;
        let ledger = Arc::new(MemoryLedger::new());
        let resolver = Arc::new(
            StaticMxResolver::new()
                .with_target("example.com", vec![server.addr()])
                .with_target("apexmail.ee", vec![server.addr()]),
        );
        let relay = Relay::new(ledger.clone(), resolver, config);
        Harness {
            relay,
            ledger,
            server,
        }
    }

    async fn ledger_row(harness: &Harness, send_unit: &str) -> QueuedSubmission {
        harness
            .ledger
            .get(send_unit)
            .await
            .expect("ledger get")
            .expect("row must exist")
    }

    #[tokio::test]
    async fn idempotent_resubmission_delivers_once_and_strips_internal_header() {
        let harness = harness(relay_config(), FakeSmtpConfig::default()).await;
        let mut request = request();
        request.message = b"X-ApexMail-Route: v1 dedicated ip-row-1 203.0.113.9\r\n\
             From: sender@apexmail.ee\r\n\
             Subject: hi\r\n\r\nbody"
            .to_vec();

        let first = harness
            .relay
            .submit(request.clone())
            .await
            .expect("first submission is accepted after DATA");
        assert_eq!(first.state, "accepted");
        assert_eq!(first.recipients.len(), 1);
        assert_eq!(first.recipients[0].outcome, RecipientOutcome::Accepted);
        assert!(first.actual_source_ip.is_some());
        assert!(
            !first.tls_used,
            "no STARTTLS advertised -> cleartext on port 25"
        );
        // No requested IP -> shared pool; never consumes dedicated warmup.
        assert!(!first.warmup_capacity_consumed());
        assert!(crate::source_ip_reply_header(&first).is_some());

        let received = harness.server.messages();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].mail_from, "sender@apexmail.ee");
        assert_eq!(received[0].recipients, vec!["user@example.com".to_string()]);
        assert!(
            !String::from_utf8_lossy(&received[0].data).contains("X-ApexMail-Route"),
            "the reserved internal route header must be stripped before delivery"
        );

        let second = harness
            .relay
            .submit(request)
            .await
            .expect("repeated send_unit returns the stored acceptance record");
        assert_eq!(second.accepted_at, first.accepted_at);
        assert_eq!(second.send_unit, first.send_unit);
        assert_eq!(
            harness.server.messages().len(),
            1,
            "a repeated send_unit must never deliver twice"
        );
    }

    #[tokio::test]
    async fn rcpt_4xx_is_retried_with_backoff() {
        let mut server_config = FakeSmtpConfig::default();
        server_config.rcpt_replies(
            "user@example.com",
            vec![
                ReplySpec::new(450, "4.2.1 mailbox busy, try later"),
                ReplySpec::ok(),
            ],
        );
        let harness = harness(relay_config(), server_config).await;

        let error = harness
            .relay
            .submit(request())
            .await
            .expect_err("4xx at RCPT must defer");
        let (attempt, next_attempt_at) = match &error {
            RelayError::RetryScheduled {
                attempt,
                next_attempt_at,
                reason,
                ..
            } => {
                assert!(reason.contains("busy"), "reason: {reason}");
                (*attempt, *next_attempt_at)
            }
            other => panic!("expected RetryScheduled, got {other:?}"),
        };
        assert_eq!(attempt, 1);
        assert!(
            harness.server.messages().is_empty(),
            "a 4xx at RCPT must not reach DATA"
        );

        let row = ledger_row(&harness, "email_queue:unit-1:user@example.com").await;
        assert_eq!(row.state, "pending");
        assert_eq!(row.attempt, 1);
        assert_eq!(row.next_attempt_at, next_attempt_at);

        let report = harness
            .relay
            .process_due(next_attempt_at + chrono::Duration::seconds(1), 10)
            .await
            .expect("due retry processes");
        assert_eq!(report.claimed, 1);
        assert_eq!(report.accepted, 1);
        assert_eq!(harness.server.messages().len(), 1);

        let row = ledger_row(&harness, "email_queue:unit-1:user@example.com").await;
        assert_eq!(row.state, "accepted");
        assert_eq!(row.attempt, 2);
        assert!(row.acceptance.is_some());
    }

    #[tokio::test]
    async fn rcpt_5xx_fails_that_recipient_and_dsns_the_sender() {
        let mut server_config = FakeSmtpConfig::default();
        server_config.rcpt_replies(
            "user@example.com",
            vec![ReplySpec::new(550, "5.1.1 user unknown")],
        );
        let harness = harness(relay_config(), server_config).await;

        let error = harness
            .relay
            .submit(request())
            .await
            .expect_err("5xx at RCPT is permanent");
        match &error {
            RelayError::Permanent {
                attempt,
                reason,
                dsn_send_units,
                ..
            } => {
                assert_eq!(*attempt, 1);
                assert!(reason.contains("5.1.1"), "reason: {reason}");
                assert_eq!(dsn_send_units.len(), 1);
            }
            other => panic!("expected Permanent, got {other:?}"),
        }
        assert!(
            harness.server.messages().is_empty(),
            "5xx at RCPT must fail before DATA"
        );
        let row = ledger_row(&harness, "email_queue:unit-1:user@example.com").await;
        assert_eq!(row.state, "failed");
        assert!(
            row.acceptance.is_none(),
            "no acceptance without post-DATA 250"
        );

        // The DSN is itself a queued submission with a null return path.
        let report = harness
            .relay
            .process_due(Utc::now() + chrono::Duration::days(1), 10)
            .await
            .expect("DSN delivery processes");
        assert_eq!(report.accepted, 1);
        let messages = harness.server.messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].mail_from, "", "DSNs use MAIL FROM:<>");
        assert_eq!(
            messages[0].recipients,
            vec!["sender@apexmail.ee".to_string()]
        );
        let dsn = String::from_utf8_lossy(&messages[0].data);
        assert!(dsn.contains("Status: 5.1.1"), "DSN: {dsn}");
        assert!(dsn.contains("Action: failed"));
        assert!(dsn.contains("Final-Recipient: rfc822; user@example.com"));
    }

    #[tokio::test]
    async fn data_5xx_produces_dsn_and_never_retries() {
        let mut server_config = FakeSmtpConfig::default();
        // First DATA (the original) is rejected after transmission; the
        // second (the DSN) is accepted.
        server_config.end_of_data = ScriptedReply::sequence(vec![
            ReplySpec::new(550, "5.7.1 message rejected after DATA"),
            ReplySpec::new(250, "2.0.0 queued"),
        ]);
        let harness = harness(relay_config(), server_config).await;

        let error = harness
            .relay
            .submit(request())
            .await
            .expect_err("5xx after DATA rejects the whole message");
        match &error {
            RelayError::Permanent { dsn_send_units, .. } => assert_eq!(dsn_send_units.len(), 1),
            other => panic!("expected Permanent, got {other:?}"),
        }
        assert_eq!(
            harness.server.messages().len(),
            1,
            "the message WAS transmitted before the end-of-DATA rejection"
        );
        let row = ledger_row(&harness, "email_queue:unit-1:user@example.com").await;
        assert_eq!(row.state, "failed");

        let report = harness
            .relay
            .process_due(Utc::now() + chrono::Duration::days(1), 10)
            .await
            .expect("DSN delivery processes");
        assert_eq!(report.claimed, 1);
        assert_eq!(report.accepted, 1, "only the DSN is claimed");
        let messages = harness.server.messages();
        assert_eq!(messages.len(), 2);
        let dsn = String::from_utf8_lossy(&messages[1].data);
        assert!(dsn.contains("Status: 5.7.1"), "DSN: {dsn}");

        // The rejected original is terminal: nothing more is claimed.
        let report = harness
            .relay
            .process_due(Utc::now() + chrono::Duration::days(2), 10)
            .await
            .expect("second sweep");
        assert_eq!(report.claimed, 0);
        assert_eq!(
            harness.server.messages().len(),
            2,
            "no retry of the original"
        );
    }

    #[tokio::test]
    async fn source_ip_that_cannot_be_bound_is_refused_before_any_connection() {
        let harness = harness(relay_config(), FakeSmtpConfig::default()).await;
        let mut request = request();
        // TEST-NET-3 is not assigned locally: bind must fail before connect.
        request.requested_source_ip = Some("203.0.113.7".parse().expect("ip"));

        let error = harness
            .relay
            .submit(request)
            .await
            .expect_err("unbindable source IP must refuse");
        match &error {
            RelayError::RetryScheduled {
                attempt, reason, ..
            } => {
                assert_eq!(*attempt, 1);
                assert!(reason.contains("source IP"), "reason: {reason}");
                assert!(reason.contains("refused before DATA"), "reason: {reason}");
            }
            other => panic!("expected RetryScheduled, got {other:?}"),
        }
        assert_eq!(
            harness.server.connections(),
            0,
            "binding is verified before the recipient-facing connection exists"
        );
        assert!(harness.server.messages().is_empty());

        let row = ledger_row(&harness, "email_queue:unit-1:user@example.com").await;
        assert_eq!(row.state, "pending", "the pre-DATA refusal stays retryable");
    }

    #[tokio::test]
    async fn no_mx_domain_is_refused_and_dsns_the_sender() {
        let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
        let ledger = Arc::new(MemoryLedger::new());
        let resolver = Arc::new(
            StaticMxResolver::new()
                .with_error(
                    "nomx.example",
                    MxError::NoMxRecords("nomx.example".to_string()),
                )
                .with_target("apexmail.ee", vec![server.addr()]),
        );
        let relay = Relay::new(ledger.clone(), resolver, relay_config());
        let mut request = request();
        request.recipients = vec!["user@nomx.example".to_string()];

        let error = relay
            .submit(request)
            .await
            .expect_err("a domain without MX must be refused");
        match &error {
            RelayError::Permanent {
                dsn_send_units,
                reason,
                ..
            } => {
                assert_eq!(dsn_send_units.len(), 1);
                assert!(reason.contains("no MX"), "reason: {reason}");
            }
            other => panic!("expected Permanent, got {other:?}"),
        }
        assert_eq!(server.connections(), 0, "no MX means no connection attempt");

        let report = relay
            .process_due(Utc::now() + chrono::Duration::days(1), 10)
            .await
            .expect("process due");
        assert_eq!(report.accepted, 1, "the DSN is delivered");
        let messages = server.messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].mail_from, "");
        assert!(String::from_utf8_lossy(&messages[0].data).contains("undeliverable"));
    }

    #[tokio::test]
    async fn tls_required_and_unavailable_is_refused_before_mail_from() {
        let mut config = relay_config();
        config.tls_policy_override = Some(TlsPolicy::StartTlsRequired);
        // The fake server does NOT advertise STARTTLS.
        let harness = harness(config, FakeSmtpConfig::default()).await;

        let error = harness
            .relay
            .submit(request())
            .await
            .expect_err("required TLS that cannot be negotiated must refuse");
        match &error {
            RelayError::RetryScheduled { reason, .. } => {
                assert!(reason.contains("TLS is required"), "reason: {reason}");
            }
            other => panic!("expected RetryScheduled, got {other:?}"),
        }
        assert_eq!(harness.server.connections(), 1, "connected, then refused");
        let commands = harness.server.commands();
        assert!(commands.iter().any(|command| command.starts_with("EHLO")));
        assert!(
            !commands
                .iter()
                .any(|command| command.starts_with("MAIL FROM")),
            "the refusal must happen before MAIL FROM: {commands:?}"
        );
        assert!(harness.server.messages().is_empty());
    }

    #[tokio::test]
    async fn null_return_path_never_generates_a_dsn() {
        let mut server_config = FakeSmtpConfig::default();
        server_config.rcpt_replies("user@example.com", vec![ReplySpec::new(550, "5.1.1 nope")]);
        let harness = harness(relay_config(), server_config).await;
        let mut request = request();
        request.envelope_from = None;

        let error = harness
            .relay
            .submit(request)
            .await
            .expect_err("permanent failure");
        match &error {
            RelayError::Permanent { dsn_send_units, .. } => {
                assert!(
                    dsn_send_units.is_empty(),
                    "a null-return-path message must never produce a DSN"
                );
            }
            other => panic!("expected Permanent, got {other:?}"),
        }
        let stats = harness.ledger.stats().await.expect("stats");
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.pending, 0, "no DSN row may be queued");

        let report = harness
            .relay
            .process_due(Utc::now() + chrono::Duration::days(1), 10)
            .await
            .expect("process due");
        assert_eq!(report.claimed, 0);
        assert!(harness.server.messages().is_empty());
    }

    #[tokio::test]
    async fn retry_ceiling_dead_letters_with_delivery_expired_dsn() {
        let mut config = relay_config();
        config.retry.max_attempts = 1;
        let mut server_config = FakeSmtpConfig::default();
        server_config.rcpt_replies("user@example.com", vec![ReplySpec::new(450, "4.2.1 busy")]);
        let harness = harness(config, server_config).await;

        let error = harness
            .relay
            .submit(request())
            .await
            .expect_err("ceiling reached");
        match &error {
            RelayError::Permanent {
                attempt,
                reason,
                dsn_send_units,
                ..
            } => {
                assert_eq!(*attempt, 1);
                assert!(reason.contains("retry ceiling"), "reason: {reason}");
                assert_eq!(dsn_send_units.len(), 1);
            }
            other => panic!("expected Permanent, got {other:?}"),
        }
        let row = ledger_row(&harness, "email_queue:unit-1:user@example.com").await;
        assert_eq!(row.state, "failed");

        let report = harness
            .relay
            .process_due(Utc::now() + chrono::Duration::days(1), 10)
            .await
            .expect("DSN delivery");
        assert_eq!(report.accepted, 1);
        let messages = harness.server.messages();
        let dsn = String::from_utf8_lossy(&messages[0].data);
        assert!(dsn.contains("Status: 4.4.7"), "DSN: {dsn}");
    }

    #[tokio::test]
    async fn partial_acceptance_pins_the_unit_and_delivers_one_copy() {
        let mut server_config = FakeSmtpConfig::default();
        server_config.rcpt_replies("b@example.com", vec![ReplySpec::new(550, "5.1.1 unknown")]);
        let harness = harness(relay_config(), server_config).await;
        let mut request = request();
        request.recipients = vec!["a@example.com".to_string(), "b@example.com".to_string()];

        let record = harness
            .relay
            .submit(request.clone())
            .await
            .expect("one recipient accepted pins the unit as accepted");
        let accepted = record
            .recipients
            .iter()
            .filter(|result| result.outcome == RecipientOutcome::Accepted)
            .count();
        let rejected = record
            .recipients
            .iter()
            .filter(|result| result.outcome == RecipientOutcome::Rejected)
            .count();
        assert_eq!(accepted, 1);
        assert_eq!(rejected, 1);
        assert_eq!(record.dsn_send_units.len(), 1);

        // Resubmitting returns the record; no second copy.
        let again = harness.relay.submit(request).await.expect("stored record");
        assert_eq!(again.accepted_at, record.accepted_at);
        assert_eq!(harness.server.messages().len(), 1);

        // Only the DSN is delivered on later sweeps.
        let report = harness
            .relay
            .process_due(Utc::now() + chrono::Duration::days(1), 10)
            .await
            .expect("process due");
        assert_eq!(report.accepted, 1);
        assert_eq!(harness.server.messages().len(), 2);
        assert_eq!(harness.server.messages()[1].mail_from, "");
    }
}
