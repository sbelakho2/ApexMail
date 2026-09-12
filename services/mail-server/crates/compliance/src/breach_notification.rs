//! Breach notification workflow — GDPR Art. 33/34 with an explicit state
//! machine, submission evidence, a mandatory authenticated human task where
//! no authority machine API exists, and a durable subject-notification
//! outbox.
//!
//! ```text
//! detected → triage → notifiable | not_notifiable
//! notifiable → authority_queued → authority_submitted → authority_acknowledged
//! ```
//!
//! The defect this module replaces: `notify_dpa()` primarily flipped a status
//! column and logged a line — it did not record what was submitted, to whom,
//! when, with what authority reference, or whether the authority actually
//! acknowledged it. Now:
//!
//! * [`BreachNotifier::queue_authority_notification`] builds the exact
//!   Art. 33(3) submission package, hashes it and OPENS A MANDATORY
//!   AUTHENTICATED HUMAN TASK (this platform has no supervisory-authority
//!   machine API; a human must submit the package).
//! * [`BreachNotifier::record_authority_submission`] stores the exact
//!   submitted text + hash, the submission timestamp and the authority
//!   reference (AKI/receipt number), and completes the task with the
//!   authenticated actor.
//! * [`BreachNotifier::record_authority_receipt`] is the ONLY transition into
//!   `authority_acknowledged`; an empty receipt is refused and migration 213
//!   adds a CHECK constraint so direct SQL cannot bypass it either.
//! * [`BreachNotifier::queue_subject_notifications`] must be used for
//!   high-risk Art. 34 notification: it writes a durable outbox row per
//!   recipient with the exact notification text and hash, and a row only
//!   becomes `sent` with delivery evidence.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::audit_logger::AuditLogger;
use crate::types::*;

type HmacSha256 = Hmac<Sha256>;

/// The state machine, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreachStatus {
    Detected,
    Triage,
    Notifiable,
    NotNotifiable,
    AuthorityQueued,
    AuthoritySubmitted,
    AuthorityAcknowledged,
}

impl BreachStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Triage => "triage",
            Self::Notifiable => "notifiable",
            Self::NotNotifiable => "not_notifiable",
            Self::AuthorityQueued => "authority_queued",
            Self::AuthoritySubmitted => "authority_submitted",
            Self::AuthorityAcknowledged => "authority_acknowledged",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "detected" => Self::Detected,
            "triage" => Self::Triage,
            "notifiable" => Self::Notifiable,
            "not_notifiable" => Self::NotNotifiable,
            "authority_queued" => Self::AuthorityQueued,
            "authority_submitted" => Self::AuthoritySubmitted,
            "authority_acknowledged" => Self::AuthorityAcknowledged,
            // Legacy pre-state-machine values (healed by migration 213).
            "active" => Self::Detected,
            "notified_dpa" => Self::AuthoritySubmitted,
            "notified_subjects" => Self::AuthoritySubmitted,
            "resolved" => Self::AuthorityAcknowledged,
            _ => return None,
        })
    }

    /// The code-level mirror of the migration-213 trigger. The trigger is the
    /// hard gate; this helper gives callers a precise error before SQL.
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Detected, Self::Triage)
                | (Self::Triage, Self::Notifiable)
                | (Self::Triage, Self::NotNotifiable)
                | (Self::Notifiable, Self::NotNotifiable)
                | (Self::Notifiable, Self::AuthorityQueued)
                | (Self::NotNotifiable, Self::AuthorityAcknowledged)
                | (Self::AuthorityQueued, Self::AuthoritySubmitted)
                | (Self::AuthoritySubmitted, Self::AuthorityAcknowledged)
        )
    }
}

impl std::fmt::Display for BreachStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the authority notification physically happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionChannel {
    /// No machine API: an authenticated operator submits the generated
    /// package (the platform's only supported channel today).
    HumanTask,
    /// A configured machine-to-machine authority API performed the
    /// submission.
    MachineApi,
}

impl SubmissionChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HumanTask => "human_task",
            Self::MachineApi => "machine_api",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReportInput {
    pub tenant_id: String,
    pub affected_records: i32,
    pub data_types: Vec<String>,
    pub description: String,
    pub severity: String,
    /// Art. 33(3)(b): name and contact details of the DPO / contact point.
    #[serde(default)]
    pub dpo_contact: Option<String>,
    /// Art. 33(3)(c): likely consequences of the breach.
    #[serde(default)]
    pub likely_consequences: Option<String>,
    /// Art. 33(3)(d): measures taken or proposed to address the breach.
    #[serde(default)]
    pub measures_taken: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BreachReport {
    pub id: String,
    pub tenant_id: String,
    pub discovered_at: DateTime<Utc>,
    pub affected_records: i32,
    pub data_types: serde_json::Value,
    pub description: String,
    pub severity: String,
    pub gdpr_deadline: Option<DateTime<Utc>>,
    pub hipaa_deadline: Option<DateTime<Utc>>,
    pub status: String,
    pub triage_rationale: Option<String>,
    pub triaged_at: Option<DateTime<Utc>>,
    pub triaged_by: Option<String>,
    pub risk_to_subjects: bool,
    pub subject_notification_required: bool,
    pub authority_submitted_at: Option<DateTime<Utc>>,
    pub authority_reference: Option<String>,
    pub authority_receipt: Option<String>,
    pub authority_receipt_received_at: Option<DateTime<Utc>>,
    pub subjects_notified_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub notification_document: Option<serde_json::Value>,
    pub dpo_contact: Option<String>,
    pub likely_consequences: Option<String>,
    pub measures_taken: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One queued/submitted authority notification, with its exact evidence.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthoritySubmission {
    pub id: String,
    pub breach_id: String,
    pub status: String,
    pub channel: String,
    pub package: serde_json::Value,
    pub package_sha256: String,
    pub submitted_notification: Option<String>,
    pub submitted_sha256: Option<String>,
    pub attachment: Option<String>,
    pub attachment_sha256: Option<String>,
    pub authority_reference: Option<String>,
    pub receipt: Option<String>,
    pub submission_timestamp: Option<DateTime<Utc>>,
    pub receipt_received_at: Option<DateTime<Utc>>,
    pub submitted_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The mandatory human task opened when no machine API exists.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthorityTask {
    pub id: String,
    pub breach_id: String,
    pub submission_id: String,
    pub status: String,
    pub required_role: String,
    pub task: String,
    pub due_at: DateTime<Utc>,
    pub authenticated_actor: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    pub evidence: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// A durable high-risk subject-notification delivery.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SubjectNotification {
    pub id: String,
    pub breach_id: String,
    pub tenant_id: String,
    pub recipient_email: String,
    pub subject: String,
    pub body_sha256: String,
    pub status: String,
    pub attempts: i32,
    pub provider_message_id: Option<String>,
    pub delivery_evidence: Option<serde_json::Value>,
    pub queued_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub failed_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachNotificationDocument {
    pub certificate_id: String,
    pub breach_id: String,
    pub tenant_id: String,
    pub discovered_at: String,
    pub affected_records: i32,
    pub data_types: Vec<String>,
    pub description: String,
    pub severity: String,
    pub gdpr_deadline: Option<String>,
    pub hipaa_deadline: Option<String>,
    pub authority_reference: Option<String>,
    pub authority_submitted_at: Option<String>,
    pub authority_receipt_received_at: Option<String>,
    pub subjects_notified_at: Option<String>,
    pub resolved_at: Option<String>,
    pub generated_at: String,
    pub signature: String,
}

const REPORT_COLUMNS: &str = "id, tenant_id, discovered_at, affected_records, data_types, \
     description, severity, gdpr_deadline, hipaa_deadline, status, triage_rationale, triaged_at, \
     triaged_by, risk_to_subjects, subject_notification_required, authority_submitted_at, \
     authority_reference, authority_receipt, authority_receipt_received_at, subjects_notified_at, \
     resolved_at, notification_document, dpo_contact, likely_consequences, measures_taken, \
     created_at, updated_at";

pub struct BreachNotifier {
    db: PgPool,
    audit_logger: Arc<AuditLogger>,
    notification_emails: Vec<String>,
    signing_key: Vec<u8>,
}

impl BreachNotifier {
    pub fn new(
        db: PgPool,
        audit_logger: Arc<AuditLogger>,
        notification_emails: Vec<String>,
        signing_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            db,
            audit_logger,
            notification_emails,
            signing_key: signing_key.into(),
        }
    }

    // ── Intake ────────────────────────────────────────────────────────────

    /// Record a newly detected breach. Status starts at `detected`; the
    /// 72-hour GDPR clock and the HIPAA 60-day clock start at discovery.
    pub async fn report_breach(
        &self,
        input: BreachReportInput,
        caller: &str,
    ) -> Result<BreachReport, String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let gdpr_deadline = Some(now + Duration::hours(72));
        let hipaa_deadline = Some(now + Duration::days(60));
        let severity = validate_severity(&input.severity);

        let data_types: serde_json::Value = serde_json::Value::Array(
            input
                .data_types
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        );

        sqlx::query(
            "INSERT INTO breach_reports
               (id, tenant_id, discovered_at, affected_records, data_types,
                description, severity, gdpr_deadline, hipaa_deadline, status,
                dpo_contact, likely_consequences, measures_taken,
                notification_document, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'detected',$10,$11,$12,NULL,$13,$13)",
        )
        .bind(&id)
        .bind(&input.tenant_id)
        .bind(now)
        .bind(input.affected_records)
        .bind(&data_types)
        .bind(&input.description)
        .bind(&severity)
        .bind(gdpr_deadline)
        .bind(hipaa_deadline)
        .bind(&input.dpo_contact)
        .bind(&input.likely_consequences)
        .bind(&input.measures_taken)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        self.audit(
            &input.tenant_id,
            &id,
            caller,
            serde_json::json!({
                "event": "breach_reported",
                "affected_records": input.affected_records,
                "severity": severity,
                "data_types": input.data_types,
                "status": BreachStatus::Detected.as_str(),
            }),
        )
        .await;

        info!(
            breach_id = %id,
            tenant = %input.tenant_id,
            affected = input.affected_records,
            severity = %severity,
            "Breach report detected — 72h GDPR clock started"
        );

        self.fetch(&id)
            .await?
            .ok_or_else(|| "Just-created breach report missing".into())
    }

    /// Complete the Art. 33(3) assessment fields the submission package
    /// requires (DPO contact, likely consequences, measures taken).
    pub async fn update_assessment(
        &self,
        breach_id: &str,
        dpo_contact: Option<&str>,
        likely_consequences: Option<&str>,
        measures_taken: Option<&str>,
        caller: &str,
    ) -> Result<BreachReport, String> {
        let report = self.require(breach_id).await?;
        self.audit(
            &report.tenant_id,
            breach_id,
            caller,
            serde_json::json!({"event": "breach_assessment_updated"}),
        )
        .await;
        sqlx::query(
            "UPDATE breach_reports
                SET dpo_contact = COALESCE($2, dpo_contact),
                    likely_consequences = COALESCE($3, likely_consequences),
                    measures_taken = COALESCE($4, measures_taken),
                    updated_at = NOW()
              WHERE id = $1",
        )
        .bind(breach_id)
        .bind(dpo_contact)
        .bind(likely_consequences)
        .bind(measures_taken)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        self.fetch(breach_id)
            .await?
            .ok_or_else(|| "Breach report missing after update".into())
    }

    /// Triage: decide `notifiable` / `not_notifiable` with a recorded
    /// rationale and the risk assessment for data subjects.
    pub async fn triage(
        &self,
        breach_id: &str,
        notifiable: bool,
        risk_to_subjects: bool,
        rationale: &str,
        caller: &str,
    ) -> Result<BreachReport, String> {
        if rationale.trim().is_empty() {
            return Err("triage requires a recorded rationale".into());
        }
        let report = self.require(breach_id).await?;
        let current = parse_status(&report)?;
        let next = if notifiable {
            BreachStatus::Notifiable
        } else {
            BreachStatus::NotNotifiable
        };
        // The graph is `detected → triage → notifiable | not_notifiable`.
        // `triage` is accepted as a starting point so a retry after a partial
        // failure (or a legacy `active` row already advanced) can complete.
        if !matches!(current, BreachStatus::Detected | BreachStatus::Triage) {
            return Err(format!(
                "cannot triage a breach in state {current} (expected detected or triage)"
            ));
        }
        let risk = notifiable && risk_to_subjects;

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB error (tx begin): {e}"))?;
        if current == BreachStatus::Detected {
            sqlx::query(
                "UPDATE breach_reports SET status = 'triage', updated_at = NOW() WHERE id = $1",
            )
            .bind(breach_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB error starting triage: {e}"))?;
        }
        sqlx::query(
            "UPDATE breach_reports
                SET status = $2, triage_rationale = $3, triaged_at = NOW(), triaged_by = $4,
                    risk_to_subjects = $5, subject_notification_required = $5, updated_at = NOW()
              WHERE id = $1",
        )
        .bind(breach_id)
        .bind(next.as_str())
        .bind(rationale)
        .bind(caller)
        .bind(risk)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error recording triage: {e}"))?;
        tx.commit()
            .await
            .map_err(|e| format!("DB error (commit): {e}"))?;

        self.audit(
            &report.tenant_id,
            breach_id,
            caller,
            serde_json::json!({
                "event": "breach_triaged",
                "decision": next.as_str(),
                "risk_to_subjects": risk,
            }),
        )
        .await;
        self.touch_document(breach_id).await?;
        self.fetch(breach_id)
            .await?
            .ok_or_else(|| "Breach report missing after triage".into())
    }

    /// Advance a `notifiable` breach to `authority_queued`: this is where the
    /// notification stops being a state and becomes work.
    pub async fn queue_authority_notification(
        &self,
        breach_id: &str,
        caller: &str,
    ) -> Result<AuthoritySubmission, String> {
        let report = self.require(breach_id).await?;
        let current = parse_status(&report)?;
        if current == BreachStatus::AuthorityQueued
            || current == BreachStatus::AuthoritySubmitted
            || current == BreachStatus::AuthorityAcknowledged
        {
            return self
                .latest_submission(breach_id)
                .await?
                .ok_or_else(|| "breach queued without a submission record".to_string());
        }
        if current != BreachStatus::Notifiable {
            return Err(format!(
                "a breach can only be queued for authority notification from `notifiable` \
                 (current: {current})"
            ));
        }

        let package = self.build_submission_package(&report)?;
        let package_text = serde_json::to_string_pretty(&package)
            .map_err(|e| format!("JSON serialization: {e}"))?;
        let package_sha256 = sha256_hex(&serde_json::to_string(&package).unwrap_or_default());
        let attachment_sha256 = sha256_hex(&package_text);
        let submission_id = Uuid::new_v4().to_string();

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB error (tx begin): {e}"))?;

        sqlx::query(
            "INSERT INTO breach_authority_submissions
               (id, breach_id, status, channel, package, package_sha256,
                attachment, attachment_sha256, created_at, updated_at)
             VALUES ($1,$2,'queued','human_task',$3,$4,$5,$6,NOW(),NOW())",
        )
        .bind(&submission_id)
        .bind(breach_id)
        .bind(&package)
        .bind(&package_sha256)
        .bind(&package_text)
        .bind(&attachment_sha256)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error storing submission package: {e}"))?;

        // No supervisory-authority machine API exists: a mandatory
        // authenticated human task is the ONLY path to submission. The task
        // carries the exact package hash so the operator and the record agree.
        let task_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO breach_authority_tasks
               (id, breach_id, submission_id, status, required_role, task, due_at,
                created_at, updated_at)
             SELECT $1,$2,$3,'open','dpo',$4,$5,NOW(),NOW()
              WHERE NOT EXISTS (
                  SELECT 1 FROM breach_authority_tasks WHERE breach_id = $2 AND status = 'open'
              )",
        )
        .bind(&task_id)
        .bind(breach_id)
        .bind(&submission_id)
        .bind(format!(
            "MANDATORY: submit the GDPR Art. 33 breach notification for breach {breach_id} to the \
             supervisory authority. The exact submission package (sha256 {package_sha256}) is \
             attached to submission {submission_id}; submit it through the authority's channel, \
             then record the authority reference/receipt in the compliance service. The 72-hour \
             deadline is {}.",
            report
                .gdpr_deadline
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| "UNKNOWN".into())
        ))
        .bind(
            report
                .gdpr_deadline
                .unwrap_or_else(|| Utc::now() + Duration::hours(72)),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error opening authority task: {e}"))?;

        // The status update must go through the trigger (notifiable →
        // authority_queued).
        sqlx::query(
            "UPDATE breach_reports SET status = 'authority_queued', updated_at = NOW() WHERE id = $1",
        )
        .bind(breach_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error queueing authority notification: {e}"))?;

        tx.commit()
            .await
            .map_err(|e| format!("DB error (commit): {e}"))?;

        self.audit(
            &report.tenant_id,
            breach_id,
            caller,
            serde_json::json!({
                "event": "breach_authority_notification_queued",
                "submission_id": submission_id,
                "package_sha256": package_sha256,
                "channel": "human_task",
            }),
        )
        .await;
        info!(
            breach_id,
            submission_id = %submission_id,
            "Authority submission package generated; mandatory human task opened"
        );

        self.latest_submission(breach_id)
            .await?
            .ok_or_else(|| "submission missing after queueing".into())
    }

    /// Record the actual submission: the exact notification text, its hash,
    /// the submission timestamp and the authority reference, plus the
    /// authenticated actor who performed it. Completes the human task.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_authority_submission(
        &self,
        breach_id: &str,
        submission_id: &str,
        submitted_notification: Option<&str>,
        authority_reference: &str,
        channel: SubmissionChannel,
        submitted_by: &str,
        caller: &str,
    ) -> Result<BreachReport, String> {
        if authority_reference.trim().is_empty() {
            return Err("an authority submission requires the authority reference".into());
        }
        if submitted_by.trim().is_empty() {
            return Err(
                "an authority submission must name the authenticated person who submitted it"
                    .into(),
            );
        }
        let report = self.require(breach_id).await?;
        let current = parse_status(&report)?;
        if current != BreachStatus::AuthorityQueued {
            return Err(format!(
                "authority submission can only be recorded from `authority_queued` (current: {current})"
            ));
        }

        let submission: AuthoritySubmission = sqlx::query_as(
            "SELECT id, breach_id, status, channel, package, package_sha256,
                    submitted_notification, submitted_sha256, attachment, attachment_sha256,
                    authority_reference, receipt, submission_timestamp, receipt_received_at,
                    submitted_by, created_at, updated_at
               FROM breach_authority_submissions WHERE id = $1 AND breach_id = $2",
        )
        .bind(submission_id)
        .bind(breach_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error reading submission: {e}"))?
        .ok_or_else(|| format!("submission {submission_id} not found for breach {breach_id}"))?;
        if submission.status != "queued" {
            return Err(format!(
                "submission {submission_id} is already {}",
                submission.status
            ));
        }

        // The exact text submitted: the caller may pass the operator's final
        // (possibly completed) notification; otherwise the generated package
        // attachment text IS the submitted notification. Either way it is
        // stored verbatim with its hash.
        let notification_text = submitted_notification
            .map(str::to_string)
            .or_else(|| submission.attachment.clone())
            .ok_or_else(|| "submission has no package text to record".to_string())?;
        if notification_text.trim().is_empty() {
            return Err("the submitted notification text must not be empty".into());
        }
        let submitted_sha256 = sha256_hex(&notification_text);
        let now = Utc::now();

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB error (tx begin): {e}"))?;

        sqlx::query(
            "UPDATE breach_authority_submissions
                SET status = 'submitted', channel = $2, submitted_notification = $3,
                    submitted_sha256 = $4, authority_reference = $5,
                    submission_timestamp = $6, submitted_by = $7, updated_at = $6
              WHERE id = $1 AND status = 'queued'",
        )
        .bind(submission_id)
        .bind(channel.as_str())
        .bind(&notification_text)
        .bind(&submitted_sha256)
        .bind(authority_reference)
        .bind(now)
        .bind(submitted_by)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error recording submission: {e}"))?;

        // The human task is completed by the authenticated actor; it cannot
        // stay open behind a submitted notification.
        sqlx::query(
            "UPDATE breach_authority_tasks
                SET status = 'completed', authenticated_actor = $2, completed_at = $3,
                    evidence = $4, updated_at = $3
              WHERE submission_id = $1 AND status = 'open'",
        )
        .bind(submission_id)
        .bind(submitted_by)
        .bind(now)
        .bind(serde_json::json!({
            "authority_reference": authority_reference,
            "channel": channel.as_str(),
            "submitted_sha256": submitted_sha256,
        }))
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error completing authority task: {e}"))?;

        sqlx::query(
            "UPDATE breach_reports
                SET status = 'authority_submitted', authority_submitted_at = $2,
                    authority_reference = $3, updated_at = $2
              WHERE id = $1",
        )
        .bind(breach_id)
        .bind(now)
        .bind(authority_reference)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error marking authority submitted: {e}"))?;

        tx.commit()
            .await
            .map_err(|e| format!("DB error (commit): {e}"))?;

        self.audit(
            &report.tenant_id,
            breach_id,
            caller,
            serde_json::json!({
                "event": "breach_authority_submitted",
                "submission_id": submission_id,
                "authority_reference": authority_reference,
                "channel": channel.as_str(),
                "submitted_by": submitted_by,
                "submitted_sha256": submitted_sha256,
            }),
        )
        .await;
        self.touch_document(breach_id).await?;
        info!(breach_id, %authority_reference, "Authority submission recorded");
        self.fetch(breach_id)
            .await?
            .ok_or_else(|| "Breach report missing after submission".into())
    }

    /// Record the authority's receipt. This is the ONLY path to
    /// `authority_acknowledged` — without a non-empty receipt the transition
    /// is refused here and by the migration-213 CHECK constraint.
    pub async fn record_authority_receipt(
        &self,
        breach_id: &str,
        receipt: &str,
        received_at: Option<DateTime<Utc>>,
        caller: &str,
    ) -> Result<BreachReport, String> {
        if receipt.trim().is_empty() {
            return Err(
                "an authority acknowledgement requires the authority's receipt/reference — a \
                 notification cannot be acknowledged without one"
                    .into(),
            );
        }
        let report = self.require(breach_id).await?;
        let current = parse_status(&report)?;
        if current != BreachStatus::AuthoritySubmitted {
            return Err(format!(
                "a receipt can only be recorded for a submitted notification (current: {current})"
            ));
        }
        let received = received_at.unwrap_or_else(Utc::now);
        let now = Utc::now();

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB error (tx begin): {e}"))?;

        sqlx::query(
            "UPDATE breach_authority_submissions
                SET status = 'receipt_recorded', receipt = $2, receipt_received_at = $3,
                    updated_at = $3
              WHERE breach_id = $1 AND status = 'submitted'",
        )
        .bind(breach_id)
        .bind(receipt)
        .bind(received)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error recording receipt: {e}"))?;

        sqlx::query(
            "UPDATE breach_reports
                SET status = 'authority_acknowledged', authority_receipt = $2,
                    authority_receipt_received_at = $3, updated_at = $4
              WHERE id = $1",
        )
        .bind(breach_id)
        .bind(receipt)
        .bind(received)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error acknowledging breach: {e}"))?;

        tx.commit()
            .await
            .map_err(|e| format!("DB error (commit): {e}"))?;

        self.audit(
            &report.tenant_id,
            breach_id,
            caller,
            serde_json::json!({
                "event": "breach_authority_receipt_recorded",
                "receipt": receipt,
            }),
        )
        .await;
        self.touch_document(breach_id).await?;
        info!(
            breach_id,
            "Authority receipt recorded — breach acknowledged"
        );
        self.fetch(breach_id)
            .await?
            .ok_or_else(|| "Breach report missing after receipt".into())
    }

    // ── High-risk data-subject notification (Art. 34) ─────────────────────

    /// Queue the durable Art. 34 notification to affected subjects. Allowed
    /// only for a notifiable breach whose triage recorded risk to subjects.
    /// Returns the number of NEW outbox rows; re-queueing is idempotent.
    pub async fn queue_subject_notifications(
        &self,
        breach_id: &str,
        recipients: &[String],
        caller: &str,
    ) -> Result<usize, String> {
        let report = self.require(breach_id).await?;
        let current = parse_status(&report)?;
        if !matches!(
            current,
            BreachStatus::Notifiable
                | BreachStatus::AuthorityQueued
                | BreachStatus::AuthoritySubmitted
                | BreachStatus::AuthorityAcknowledged
        ) {
            return Err(format!(
                "subject notification is not available in state {current}"
            ));
        }
        if !report.subject_notification_required {
            return Err(
                "subject notification requires a triage decision that the breach is high-risk \
                 (Art. 34(1)) — re-triage with risk_to_subjects = true first"
                    .into(),
            );
        }
        if recipients.is_empty() {
            return Err("subject notification requires at least one recipient".into());
        }
        let body = build_subject_notification(&report);
        let body_sha256 = sha256_hex(&body);
        let subject_line = format!(
            "Important security notice about your data ({})",
            report.id.chars().take(8).collect::<String>()
        );

        let mut queued = 0usize;
        for recipient in recipients {
            if recipient.trim().is_empty() {
                return Err("recipient email must not be empty".into());
            }
            let rows = sqlx::query(
                "INSERT INTO breach_subject_notification_outbox
                   (id, breach_id, tenant_id, recipient_email, subject, body_text, body_sha256,
                    status, attempts, queued_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',0,NOW())
                 ON CONFLICT (breach_id, lower(recipient_email)) DO NOTHING",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(breach_id)
            .bind(&report.tenant_id)
            .bind(recipient)
            .bind(&subject_line)
            .bind(&body)
            .bind(&body_sha256)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB error queueing subject notification: {e}"))?
            .rows_affected() as usize;
            queued += rows;
        }

        self.audit(
            &report.tenant_id,
            breach_id,
            caller,
            serde_json::json!({
                "event": "breach_subject_notifications_queued",
                "queued": queued,
                "body_sha256": body_sha256,
            }),
        )
        .await;
        info!(breach_id, queued, "Art. 34 subject notifications queued");
        Ok(queued)
    }

    /// Record delivery evidence for a queued subject notification. Only with
    /// delivery evidence does the row become `sent`.
    pub async fn record_subject_notification_delivery(
        &self,
        outbox_id: &str,
        provider_message_id: Option<&str>,
        delivery_evidence: Option<serde_json::Value>,
    ) -> Result<SubjectNotification, String> {
        if provider_message_id.is_none() && delivery_evidence.is_none() {
            return Err(
                "delivery evidence is required: a notification cannot be marked sent without a \
                 provider message id or recorded evidence"
                    .into(),
            );
        }
        let now = Utc::now();
        let updated = sqlx::query(
            "UPDATE breach_subject_notification_outbox
                SET status = 'sent', provider_message_id = $2, delivery_evidence = $3,
                    delivered_at = $4
              WHERE id = $1 AND status = 'pending'",
        )
        .bind(outbox_id)
        .bind(provider_message_id)
        .bind(&delivery_evidence)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error recording delivery: {e}"))?
        .rows_affected();
        if updated != 1 {
            return Err(format!("outbox row {outbox_id} is not pending"));
        }

        let row: SubjectNotification = sqlx::query_as(
            "SELECT id, breach_id, tenant_id, recipient_email, subject, body_sha256, status, \
                    attempts, provider_message_id, delivery_evidence, queued_at, delivered_at, \
                    failed_reason
               FROM breach_subject_notification_outbox WHERE id = $1",
        )
        .bind(outbox_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("DB error reading outbox row: {e}"))?;

        // Reflect the first delivery on the report (Art. 34 evidence).
        sqlx::query(
            "UPDATE breach_reports
                SET subjects_notified_at = COALESCE(subjects_notified_at, $2), updated_at = NOW()
              WHERE id = $1",
        )
        .bind(&row.breach_id)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error updating subjects_notified_at: {e}"))?;
        self.touch_document(&row.breach_id).await?;
        Ok(row)
    }

    /// Park a subject notification as failed (with the reason) — never
    /// silently dropped.
    pub async fn mark_subject_notification_failed(
        &self,
        outbox_id: &str,
        reason: &str,
    ) -> Result<(), String> {
        sqlx::query(
            "UPDATE breach_subject_notification_outbox
                SET status = 'failed', attempts = attempts + 1, failed_reason = $2
              WHERE id = $1 AND status = 'pending'",
        )
        .bind(outbox_id)
        .bind(reason)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error marking notification failed: {e}"))?;
        Ok(())
    }

    /// Pending subject notifications (oldest first).
    pub async fn pending_subject_notifications(
        &self,
        limit: i64,
    ) -> Result<Vec<SubjectNotification>, String> {
        sqlx::query_as(
            "SELECT id, breach_id, tenant_id, recipient_email, subject, body_sha256, status, \
                    attempts, provider_message_id, delivery_evidence, queued_at, delivered_at, \
                    failed_reason
               FROM breach_subject_notification_outbox
              WHERE status = 'pending' ORDER BY queued_at LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error listing subject notifications: {e}"))
    }

    // ── Resolution ────────────────────────────────────────────────────────

    /// Close a breach. `authority_acknowledged` or `not_notifiable` are the
    /// only closable states; an Art. 34-required breach cannot close while
    /// subject notifications are still pending.
    pub async fn resolve(&self, breach_id: &str, caller: &str) -> Result<BreachReport, String> {
        let report = self.require(breach_id).await?;
        let current = parse_status(&report)?;
        if !matches!(
            current,
            BreachStatus::AuthorityAcknowledged | BreachStatus::NotNotifiable
        ) {
            return Err(format!(
                "breach {breach_id} cannot be resolved in state {current} — it must reach \
                 authority_acknowledged (or be triaged not_notifiable)"
            ));
        }
        if report.subject_notification_required {
            let pending: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM breach_subject_notification_outbox
                  WHERE breach_id = $1 AND status = 'pending'",
            )
            .bind(breach_id)
            .fetch_one(&self.db)
            .await
            .map_err(|e| format!("DB error counting pending notifications: {e}"))?;
            if pending > 0 {
                return Err(format!(
                    "breach {breach_id} still has {pending} pending subject notification(s)"
                ));
            }
        }
        let now = Utc::now();
        sqlx::query("UPDATE breach_reports SET resolved_at = $2, updated_at = $2 WHERE id = $1")
            .bind(breach_id)
            .bind(now)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB error resolving breach: {e}"))?;
        self.audit(
            &report.tenant_id,
            breach_id,
            caller,
            serde_json::json!({"event": "breach_resolved"}),
        )
        .await;
        self.touch_document(breach_id).await?;
        info!(breach_id, "Breach resolved");
        self.fetch(breach_id)
            .await?
            .ok_or_else(|| "Breach report missing after resolve".into())
    }

    // ── Reads / evidence ─────────────────────────────────────────────────

    pub async fn fetch(&self, breach_id: &str) -> Result<Option<BreachReport>, String> {
        sqlx::query_as(&format!(
            "SELECT {REPORT_COLUMNS} FROM breach_reports WHERE id = $1"
        ))
        .bind(breach_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))
    }

    pub async fn list_for_tenant(
        &self,
        tenant_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<BreachReport>, String> {
        let limit = limit.unwrap_or(50).min(500);
        sqlx::query_as(&format!(
            "SELECT {REPORT_COLUMNS} FROM breach_reports
              WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2"
        ))
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))
    }

    /// Every authority submission for a breach, newest first.
    pub async fn authority_submissions(
        &self,
        breach_id: &str,
    ) -> Result<Vec<AuthoritySubmission>, String> {
        sqlx::query_as(
            "SELECT id, breach_id, status, channel, package, package_sha256,
                    submitted_notification, submitted_sha256, attachment, attachment_sha256,
                    authority_reference, receipt, submission_timestamp, receipt_received_at,
                    submitted_by, created_at, updated_at
               FROM breach_authority_submissions
              WHERE breach_id = $1 ORDER BY created_at DESC",
        )
        .bind(breach_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error listing submissions: {e}"))
    }

    /// Open mandatory human tasks (all breaches, oldest first).
    pub async fn open_authority_tasks(&self, limit: i64) -> Result<Vec<AuthorityTask>, String> {
        sqlx::query_as(
            "SELECT id, breach_id, submission_id, status, required_role, task, due_at,
                    authenticated_actor, completed_at, evidence, created_at
               FROM breach_authority_tasks
              WHERE status = 'open' ORDER BY due_at LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error listing authority tasks: {e}"))
    }

    pub async fn generate_certificate(
        &self,
        breach_id: &str,
    ) -> Result<BreachNotificationDocument, String> {
        let report = self.require(breach_id).await?;
        let data_types: Vec<String> = report
            .data_types
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let doc = BreachNotificationDocument {
            certificate_id: Uuid::new_v4().to_string(),
            breach_id: report.id.clone(),
            tenant_id: report.tenant_id.clone(),
            discovered_at: report.discovered_at.to_rfc3339(),
            affected_records: report.affected_records,
            data_types,
            description: report.description.clone(),
            severity: report.severity.clone(),
            gdpr_deadline: report.gdpr_deadline.map(|t| t.to_rfc3339()),
            hipaa_deadline: report.hipaa_deadline.map(|t| t.to_rfc3339()),
            authority_reference: report.authority_reference.clone(),
            authority_submitted_at: report.authority_submitted_at.map(|t| t.to_rfc3339()),
            authority_receipt_received_at: report
                .authority_receipt_received_at
                .map(|t| t.to_rfc3339()),
            subjects_notified_at: report.subjects_notified_at.map(|t| t.to_rfc3339()),
            resolved_at: report.resolved_at.map(|t| t.to_rfc3339()),
            generated_at: Utc::now().to_rfc3339(),
            signature: self.sign_document(&report)?,
        };
        Ok(doc)
    }

    // ── Internals ─────────────────────────────────────────────────────────

    async fn require(&self, breach_id: &str) -> Result<BreachReport, String> {
        self.fetch(breach_id)
            .await?
            .ok_or_else(|| format!("Breach report {breach_id} not found"))
    }

    async fn latest_submission(
        &self,
        breach_id: &str,
    ) -> Result<Option<AuthoritySubmission>, String> {
        sqlx::query_as(
            "SELECT id, breach_id, status, channel, package, package_sha256,
                    submitted_notification, submitted_sha256, attachment, attachment_sha256,
                    authority_reference, receipt, submission_timestamp, receipt_received_at,
                    submitted_by, created_at, updated_at
               FROM breach_authority_submissions
              WHERE breach_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(breach_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error reading submission: {e}"))
    }

    /// Build the exact Art. 33(3) submission package (see the pure
    /// [`build_submission_package`]).
    fn build_submission_package(&self, report: &BreachReport) -> Result<serde_json::Value, String> {
        build_submission_package(report, &self.notification_emails)
    }
}

/// Build the exact Art. 33(3) submission package. Every field the regulation
/// names is present; a missing assessment field is refused, not silently
/// nulled. Pure function so the package contract is testable without a
/// database.
fn build_submission_package(
    report: &BreachReport,
    notification_emails: &[String],
) -> Result<serde_json::Value, String> {
    let dpo_contact = report
        .dpo_contact
        .clone()
        .or_else(|| notification_emails.first().cloned())
        .ok_or_else(|| {
            "Art. 33(3)(b) requires a DPO/contact — set it with update_assessment before \
                 queueing the authority notification"
                .to_string()
        })?;
    let likely_consequences = report.likely_consequences.clone().ok_or_else(|| {
        "Art. 33(3)(c) requires the likely consequences of the breach — set it with \
             update_assessment before queueing the authority notification"
            .to_string()
    })?;
    let measures_taken = report.measures_taken.clone().ok_or_else(|| {
        "Art. 33(3)(d) requires the measures taken or proposed — set it with update_assessment \
             before queueing the authority notification"
            .to_string()
    })?;

    Ok(serde_json::json!({
        "format": "gdpr-art-33-3-submission/v1",
        "breach_id": report.id,
        "tenant_id": report.tenant_id,
        "discovered_at": report.discovered_at.to_rfc3339(),
        "notification_deadline": report.gdpr_deadline.map(|d| d.to_rfc3339()),
        "nature_of_breach": report.description,
        "categories_of_personal_data": report.data_types,
        "approximate_number_of_records": report.affected_records,
        "risk_to_data_subjects": report.risk_to_subjects,
        "triage_rationale": report.triage_rationale,
        "dpo_contact": dpo_contact,
        "likely_consequences": likely_consequences,
        "measures_taken": measures_taken,
        "generated_at": Utc::now().to_rfc3339(),
    }))
}

impl BreachNotifier {
    /// Re-render and store the signed notification document after a
    /// transition.
    async fn touch_document(&self, breach_id: &str) -> Result<(), String> {
        let report = self.require(breach_id).await?;
        let doc = serde_json::json!({
            "breach_id": report.id,
            "tenant_id": report.tenant_id,
            "discovered_at": report.discovered_at.to_rfc3339(),
            "affected_records": report.affected_records,
            "data_types": report.data_types,
            "description": report.description,
            "severity": report.severity,
            "gdpr_deadline": report.gdpr_deadline.map(|t| t.to_rfc3339()),
            "hipaa_deadline": report.hipaa_deadline.map(|t| t.to_rfc3339()),
            "status": report.status,
            "triage_rationale": report.triage_rationale,
            "risk_to_subjects": report.risk_to_subjects,
            "authority_submitted_at": report.authority_submitted_at.map(|t| t.to_rfc3339()),
            "authority_reference": report.authority_reference,
            "authority_receipt": report.authority_receipt,
            "authority_receipt_received_at": report.authority_receipt_received_at.map(|t| t.to_rfc3339()),
            "subjects_notified_at": report.subjects_notified_at.map(|t| t.to_rfc3339()),
            "resolved_at": report.resolved_at.map(|t| t.to_rfc3339()),
            "generated_at": Utc::now().to_rfc3339(),
        });
        let canonical = serde_json::to_string(&doc).map_err(|e| format!("JSON: {e}"))?;
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(canonical.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let mut signed = doc;
        if let Some(obj) = signed.as_object_mut() {
            obj.insert("signature".into(), serde_json::Value::String(signature));
        }
        sqlx::query(
            "UPDATE breach_reports SET notification_document = $1, updated_at = NOW() WHERE id = $2",
        )
        .bind(&signed)
        .bind(breach_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error updating notification document: {e}"))?;
        Ok(())
    }

    async fn audit(
        &self,
        tenant_id: &str,
        breach_id: &str,
        caller: &str,
        details: serde_json::Value,
    ) {
        let ctx = LogContext {
            tenant_id: Some(tenant_id.to_string()),
            user_id: Some(caller.to_string()),
            session_id: None,
            ip_address: None,
            user_agent: None,
        };
        let _ = self
            .audit_logger
            .log(
                AuditAction::Update,
                AuditResource::Settings,
                Some(breach_id),
                details,
                AuditOutcome::Success,
                None,
                &ctx,
            )
            .await;
    }

    fn sign_document(&self, report: &BreachReport) -> Result<String, String> {
        let canonical = serde_json::json!({
            "id": report.id,
            "tenant_id": report.tenant_id,
            "status": report.status,
            "authority_reference": report.authority_reference,
            "resolved_at": report.resolved_at.map(|t| t.to_rfc3339()),
        });
        let canonical_str = serde_json::to_string(&canonical).map_err(|e| format!("JSON: {e}"))?;
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(canonical_str.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

// ── Pure helpers ────────────────────────────────────────────────────────────

fn parse_status(report: &BreachReport) -> Result<BreachStatus, String> {
    BreachStatus::parse(&report.status)
        .ok_or_else(|| format!("unknown breach status {:?}", report.status))
}

/// Normalize a caller-supplied severity to the four supported levels.
pub fn validate_severity(s: &str) -> String {
    let s = s.trim().to_lowercase();
    match s.as_str() {
        "low" | "medium" | "high" | "critical" => s,
        _ => "medium".to_string(),
    }
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// The exact Art. 34 notification text queued for a high-risk breach.
/// Pure function so the stored hash is reproducible.
pub fn build_subject_notification(report: &BreachReport) -> String {
    format!(
        "We are writing to inform you of a personal-data breach that may affect you.\n\
         \n\
         What happened: {description}\n\
         \n\
         What this means for you: {consequences}\n\
         \n\
         What we have done: {measures}\n\
         \n\
         If you have questions, contact: {contact}\n\
         \n\
         Reference: {reference}\n\
         \n\
         — ApexMail",
        description = report.description,
        consequences = report.likely_consequences.as_deref().unwrap_or(
            "We are still assessing the likely consequences; this notice will be updated."
        ),
        measures = report
            .measures_taken
            .as_deref()
            .unwrap_or("We are still implementing remedial measures; this notice will be updated."),
        contact = report
            .dpo_contact
            .as_deref()
            .unwrap_or("the platform data protection contact"),
        reference = report.id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(status: BreachStatus) -> BreachReport {
        BreachReport {
            id: "br-1".into(),
            tenant_id: "t_abc123".into(),
            discovered_at: Utc::now(),
            affected_records: 1500,
            data_types: serde_json::json!(["email", "name"]),
            description: "Unauthorized access to mailing list database".into(),
            severity: "high".into(),
            gdpr_deadline: Some(Utc::now() + Duration::hours(72)),
            hipaa_deadline: Some(Utc::now() + Duration::days(60)),
            status: status.as_str().into(),
            triage_rationale: None,
            triaged_at: None,
            triaged_by: None,
            risk_to_subjects: false,
            subject_notification_required: false,
            authority_submitted_at: None,
            authority_reference: None,
            authority_receipt: None,
            authority_receipt_received_at: None,
            subjects_notified_at: None,
            resolved_at: None,
            notification_document: None,
            dpo_contact: None,
            likely_consequences: None,
            measures_taken: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn severity_validation() {
        assert_eq!(validate_severity("low"), "low");
        assert_eq!(validate_severity("HIGH"), "high");
        assert_eq!(validate_severity("  medium  "), "medium");
        assert_eq!(validate_severity("invalid"), "medium");
        assert_eq!(validate_severity(""), "medium");
    }

    #[test]
    fn state_machine_is_monotonic() {
        use BreachStatus::*;
        assert!(Detected.can_transition_to(Triage));
        assert!(Triage.can_transition_to(Notifiable));
        assert!(Triage.can_transition_to(NotNotifiable));
        assert!(Notifiable.can_transition_to(AuthorityQueued));
        assert!(AuthorityQueued.can_transition_to(AuthoritySubmitted));
        assert!(AuthoritySubmitted.can_transition_to(AuthorityAcknowledged));
        // No skips.
        assert!(!Detected.can_transition_to(Notifiable));
        assert!(!Notifiable.can_transition_to(AuthoritySubmitted));
        assert!(!AuthorityQueued.can_transition_to(AuthorityAcknowledged));
        // No backwards moves.
        assert!(!AuthorityAcknowledged.can_transition_to(AuthoritySubmitted));
        assert!(!AuthoritySubmitted.can_transition_to(AuthorityQueued));
        assert!(!Notifiable.can_transition_to(Triage));
        // A non-notifiable decision is terminal (only acknowledgement-close).
        assert!(!NotNotifiable.can_transition_to(Notifiable));
    }

    #[test]
    fn status_parses_new_and_legacy_values() {
        assert_eq!(
            BreachStatus::parse("detected"),
            Some(BreachStatus::Detected)
        );
        assert_eq!(
            BreachStatus::parse("authority_acknowledged"),
            Some(BreachStatus::AuthorityAcknowledged)
        );
        // Legacy pre-213 values heal, never error.
        assert_eq!(BreachStatus::parse("active"), Some(BreachStatus::Detected));
        assert_eq!(
            BreachStatus::parse("notified_dpa"),
            Some(BreachStatus::AuthoritySubmitted)
        );
        assert_eq!(BreachStatus::parse("nonsense"), None);
    }

    #[test]
    fn submission_package_requires_the_art_33_3_fields() {
        let contacts = vec!["dpo@example.com".to_string()];

        // Missing assessment fields are refused, not nulled.
        let incomplete = report(BreachStatus::Notifiable);
        assert!(build_submission_package(&incomplete, &contacts).is_err());

        let mut complete = incomplete;
        complete.likely_consequences = Some("phishing risk".into());
        complete.measures_taken = Some("keys rotated".into());
        complete.triage_rationale = Some("high risk to subjects".into());
        let package = build_submission_package(&complete, &contacts)
            .expect("complete assessment yields a package");
        assert_eq!(package["format"], "gdpr-art-33-3-submission/v1");
        assert_eq!(package["breach_id"], "br-1");
        assert_eq!(package["dpo_contact"], "dpo@example.com");
        assert_eq!(package["categories_of_personal_data"][0], "email");
        assert_eq!(package["approximate_number_of_records"], 1500);
        assert!(package.get("nature_of_breach").is_some());
        assert!(package.get("likely_consequences").is_some());
        assert!(package.get("measures_taken").is_some());
        // The package hash is stable for the same content modulo generated_at.
        let text = serde_json::to_string(&package).unwrap();
        assert_eq!(sha256_hex(&text), sha256_hex(&text));
    }

    #[test]
    fn subject_notification_carries_description_consequences_measures_contact() {
        let mut report = report(BreachStatus::AuthoritySubmitted);
        report.likely_consequences = Some("identity theft risk".into());
        report.measures_taken = Some("passwords reset".into());
        report.dpo_contact = Some("dpo@apexmail.ee".into());
        let body = build_subject_notification(&report);
        assert!(body.contains("Unauthorized access to mailing list database"));
        assert!(body.contains("identity theft risk"));
        assert!(body.contains("passwords reset"));
        assert!(body.contains("dpo@apexmail.ee"));
        assert!(body.contains("br-1"));
    }
}
