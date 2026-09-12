//! GDPR automation — data-subject request lifecycle (access, erasure,
//! portability, rectification, restriction, objection), consent
//! management, double opt-in, and queue-based bulk processing.
//!
//! Request flow:pending_verification → verified → processing → completed/rejected/expired
//! Verification:SHA-256 token hash ↔ stored hash.
//! Erasure (Art.17):one canonical data map ([`erasure_stores`]) — deletes from
//! the event/contact/consent stores, anonymizes messages/users/invoices,
//! tombstones the account, and submits a best-effort ClickHouse purge.
//! Access/Portability:the SAME store set ([`export_store_names`]) — the maps
//! mirror each other (audit F9).
//! Consent:Upsert on (tenant_id, subscriber_id, consent_type). Marketing
//! cascade:withdrawing marketing revokes analytics and profiling.

use chrono::{DateTime, Duration, Months, TimeDelta, Utc};
use deadpool_redis::Pool as RedisPool;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// HMAC-SHA256 type for consent certificate signing.
type HmacSha256 = Hmac<Sha256>;

use crate::legal_archive;
use crate::retention_classes;

/// The maximum extension authorised by GDPR Art. 12(3): two further months.
pub const MAX_EXTENSION_MONTHS: u32 = 2;

/// Statutory response deadline: ONE CALENDAR MONTH from receipt (Art. 12(3)).
///
/// Calendar arithmetic, not a fixed number of days: 2026-01-31 must fall due
/// on 2026-02-28, and a fixed 30x24h interval would disagree across month
/// boundaries. The persisted `statutory_due_at` column is authoritative for a
/// stored request; this is the computation that produced it.
pub fn statutory_due_at(received_at: DateTime<Utc>) -> DateTime<Utc> {
    received_at
        .checked_add_months(Months::new(1))
        .unwrap_or(received_at + Duration::days(30))
}

/// Extended deadline: the statutory deadline plus up to two further months.
pub fn extended_due_at(statutory_due_at: DateTime<Utc>) -> DateTime<Utc> {
    statutory_due_at
        .checked_add_months(Months::new(MAX_EXTENSION_MONTHS))
        .unwrap_or(statutory_due_at + Duration::days(60))
}

/// Validate an extension request. An extension must be JUSTIFIED (a real
/// reason) and NOTIFIED (the timestamp at which the subject was informed);
/// a bare "extended" flag is exactly the defect this replaces.
pub fn validate_extension(
    reason: &str,
    notified_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
) -> Result<(), String> {
    if reason.trim().is_empty() {
        return Err("an extension requires a recorded reason (Art. 12(3))".into());
    }
    if reason.trim().len() < 10 {
        return Err("the extension reason is too short to be a justification".into());
    }
    if notified_at < received_at {
        return Err("the extension notification cannot precede the request's receipt".into());
    }
    if notified_at > Utc::now() + Duration::minutes(5) {
        return Err("the extension notification timestamp cannot be in the future".into());
    }
    Ok(())
}

/// One pending verification-token delivery in the outbox.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct DsrOutboxEntry {
    pub id: String,
    pub request_id: String,
    pub tenant_id: String,
    pub email: String,
    pub verification_token: String,
    pub verify_url: String,
    pub status: String,
    pub attempts: i32,
    pub created_at: chrono::DateTime<Utc>,
    pub sent_at: Option<chrono::DateTime<Utc>>,
}

use crate::config::GdprConfig;
use crate::types::*;

pub struct GdprAutomation {
    db: PgPool,
    redis: RedisPool,
    config: GdprConfig,
}

impl GdprAutomation {
    pub fn new(db: PgPool, redis: RedisPool, config: GdprConfig) -> Self {
        Self { db, redis, config }
    }

    // ── Request Lifecycle ────────────────────────────────────

    /// Pending verification-token deliveries, oldest first — the queue the
    /// crate's outbox flush job (`dsr_outbox_flush`) drains into
    /// `email_queue` under the system sender.
    pub async fn pending_verification_outbox(
        &self,
        limit: i64,
    ) -> Result<Vec<DsrOutboxEntry>, String> {
        let rows: Vec<DsrOutboxEntry> = sqlx::query_as(
            "SELECT id, request_id, tenant_id, email, verification_token,
                    verify_url, status, attempts, created_at, sent_at
             FROM dsr_verification_outbox
             WHERE status = 'pending'
             ORDER BY created_at
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(rows)
    }

    /// Mark an outbox entry as sent (called by the mail-owning service after
    /// successful delivery).
    pub async fn mark_outbox_sent(&self, id: &str) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE dsr_verification_outbox
             SET status = 'sent', sent_at = NOW()
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        if updated.rows_affected() != 1 {
            return Err(format!("outbox entry {id} not pending"));
        }
        Ok(())
    }

    /// Submit a new data-subject request. Returns request + verification token.
    ///
    /// D (outbox): the raw verification token is written to
    /// `dsr_verification_outbox` in the SAME transaction as the request —
    /// without the outbox row the subject can never receive the token, so a
    /// failed write fails the submission. Delivery is the flush job's half
    /// of the handoff: `dsr_outbox_flush` reads pending rows
    /// ([`Self::pending_verification_outbox`]), queues the verification
    /// email into `email_queue` under the system sender, and marks it sent
    /// ([`Self::mark_outbox_sent`] shape).
    pub async fn submit_request(
        &self,
        tenant_id: &str,
        request_type: DataSubjectRequestType,
        email: &str,
    ) -> Result<(DataSubjectRequest, String), String> {
        let id = Uuid::new_v4().to_string();
        let token = Uuid::new_v4().to_string();
        let token_hash = sha256_hex(&token);
        let now = Utc::now();
        let expires_at = now + Duration::days(self.config.request_expiration_days);
        let verify_url = format!("{}/gdpr/verify/{}", self.config.verify_base_url, id);

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        // GDPR Art. 12(3): the response clock starts at RECEIPT. The due date
        // is persisted at intake (one calendar month), so a later config
        // change cannot move it, and identity verification is recorded as its
        // own event without restarting the clock.
        let statutory_due = statutory_due_at(now);
        sqlx::query(
            "INSERT INTO data_subject_requests
               (id, tenant_id, request_type, email, verification_token_hash,
                verified, status, requested_at, expires_at, received_at, statutory_due_at)
             VALUES ($1,$2,$3,$4,$5,false,'pending_verification',$6,$7,$6,$8)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(request_type.to_string())
        .bind(email)
        .bind(&token_hash)
        .bind(now)
        .bind(expires_at)
        .bind(statutory_due)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        sqlx::query(
            "INSERT INTO dsr_verification_outbox
               (id, request_id, tenant_id, email, verification_token,
                verify_url, status, attempts, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,'pending',0,$7)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&id)
        .bind(tenant_id)
        .bind(email)
        .bind(&token)
        .bind(&verify_url)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error (dsr_verification_outbox): {e}"))?;

        // CP visibility (surgical mirror): the control plane's admin
        // dashboard (gdpr_pending count) and admin/gdpr.rs list read the
        // `gdpr_requests` table. F13: the mirror write happens AFTER the
        // intake transaction commits, best-effort with its own error
        // handling — a CP-side shape drift (the table is CP-owned) must not
        // fail the subject's DSR submission, which is durable on its own.
        // The id column is VARCHAR(26), so the 36-char UUID cannot be
        // reused; a prefixed 22-hex id fits exactly.

        tx.commit().await.map_err(|e| format!("DB error: {e}"))?;

        let cp_request_id = format!("gdr_{}", &Uuid::new_v4().simple().to_string()[..22]);
        if let Err(e) = sqlx::query(
            "INSERT INTO gdpr_requests
               (id, tenant_id, email, request_type, status, token_hash, created_at, updated_at)
             VALUES ($1,$2,$3,$4,'pending',$5,$6,$6)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&cp_request_id)
        .bind(tenant_id)
        .bind(email)
        .bind(request_type.to_string())
        .bind(&token_hash)
        .bind(now)
        .execute(&self.db)
        .await
        {
            warn!(
                request_id = %id,
                error = %e,
                "GDPR: CP gdpr_requests mirror write failed (best-effort) — the DSR itself is committed"
            );
        }

        let request = DataSubjectRequest {
            id,
            tenant_id: tenant_id.into(),
            request_type,
            email: email.into(),
            verification_token_hash: token_hash,
            verified: false,
            verified_at: None,
            status: RequestStatus::PendingVerification,
            requested_at: now,
            processed_at: None,
            completed_at: None,
            expires_at,
            result: None,
            received_at: Some(now),
            identity_verified_at: None,
            statutory_due_at: Some(statutory_due),
            extension_due_at: None,
            extension_reason: None,
            extension_notified_at: None,
        };

        info!(request_id = %request.id, %request_type, "GDPR request submitted");
        Ok((request, token))
    }

    /// Verify a data-subject request using the token.
    pub async fn verify_request(&self, request_id: &str, token: &str) -> Result<bool, String> {
        let token_hash = sha256_hex(token);

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT verification_token_hash FROM data_subject_requests
             WHERE id = $1 AND status = 'pending_verification'
             FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let (stored_hash,) = match row {
            Some(r) => r,
            None => return Ok(false),
        };

        if !constant_time_compare(&token_hash, &stored_hash) {
            return Ok(false);
        }

        // `identity_verified_at` is its own clock event: verification proves
        // who is asking, it does not restart the Art. 12(3) response period.
        let updated = sqlx::query(
            "UPDATE data_subject_requests
             SET status = 'verified', verified = true, verified_at = NOW(),
                 identity_verified_at = NOW()
             WHERE id = $1 AND status = 'pending_verification'",
        )
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        if updated.rows_affected() != 1 {
            return Ok(false);
        }

        tx.commit().await.map_err(|e| format!("DB error: {e}"))?;

        // Enqueue for processing
        self.enqueue_request(request_id).await?;

        info!(request_id, "GDPR request verified");
        Ok(true)
    }

    /// Extend a request's statutory deadline (Art. 12(3): up to two further
    /// months for complex requests). The extension MUST be justified and the
    /// subject MUST have been notified: an empty reason or a missing
    /// notification timestamp is refused, and the DB CHECK constraint
    /// (migration 213) rejects a direct SQL extension without both.
    pub async fn extend_request(
        &self,
        request_id: &str,
        reason: &str,
        extension_notified_at: DateTime<Utc>,
    ) -> Result<DataSubjectRequest, String> {
        let request = self
            .fetch_request(request_id)
            .await?
            .ok_or("Request not found")?;
        let received_at = request
            .received_at
            .ok_or("Request has no receipt timestamp — cannot compute the statutory clock")?;
        validate_extension(reason, extension_notified_at, received_at)?;
        let statutory_due = request
            .statutory_due_at
            .unwrap_or_else(|| statutory_due_at(received_at));
        let extension_due = extended_due_at(statutory_due);

        sqlx::query(
            "UPDATE data_subject_requests
                SET extension_due_at = $2, extension_reason = $3, extension_notified_at = $4
              WHERE id = $1",
        )
        .bind(request_id)
        .bind(extension_due)
        .bind(reason.trim())
        .bind(extension_notified_at)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error recording extension: {e}"))?;

        info!(
            request_id,
            extension_due = %extension_due,
            "GDPR request extended (justified and notified)"
        );
        self.fetch_request(request_id)
            .await?
            .ok_or_else(|| "Request missing after extension".into())
    }

    /// Whether an open request is past its statutory deadline (extended
    /// deadline when an extension was recorded). Pure decision on the stored
    /// clock — no configuration is consulted.
    pub fn is_statutorily_overdue(request: &DataSubjectRequest, now: DateTime<Utc>) -> bool {
        let due = request.extension_due_at.or(request.statutory_due_at);
        match due {
            Some(due) => {
                now > due
                    && !matches!(
                        request.status,
                        RequestStatus::Completed
                            | RequestStatus::Rejected
                            | RequestStatus::Expired
                            | RequestStatus::Failed
                    )
            }
            None => false,
        }
    }

    /// Process a single request (called from queue worker).
    pub async fn process_request(
        &self,
        request_id: &str,
    ) -> Result<DataSubjectRequestResult, String> {
        // Mark as processing
        sqlx::query(
            "UPDATE data_subject_requests SET status = 'processing', processed_at = NOW()
             WHERE id = $1",
        )
        .bind(request_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let request = self
            .fetch_request(request_id)
            .await?
            .ok_or("Request not found")?;

        let result = match request.request_type {
            DataSubjectRequestType::Access => self.process_access_request(&request).await,
            DataSubjectRequestType::Erasure => self.process_erasure_request(&request).await,
            DataSubjectRequestType::Portability => self.process_portability_request(&request).await,
            DataSubjectRequestType::Rectification => {
                self.process_rectification_request(&request).await
            }
            DataSubjectRequestType::Restriction => self.process_restriction_request(&request).await,
            DataSubjectRequestType::Objection => self.process_objection_request(&request).await,
        };

        match &result {
            Ok(r) => {
                let is_rejected = r.rejection_reason.is_some();
                // B/F: honest terminal statuses — rectification needs human
                // review, partial erasure must not claim full completion.
                let new_status = if is_rejected {
                    "rejected"
                } else if request.request_type == DataSubjectRequestType::Rectification {
                    "pending_manual_review"
                } else if r.partial == Some(true) {
                    "partial"
                } else {
                    "completed"
                };
                let result_json = serde_json::to_value(r).ok();
                sqlx::query(
                    "UPDATE data_subject_requests
                     SET status = $1,
                         completed_at = CASE WHEN $1 IN ('completed', 'partial', 'rejected')
                                             THEN NOW() ELSE NULL END,
                         result = $2
                     WHERE id = $3",
                )
                .bind(new_status)
                .bind(&result_json)
                .bind(request_id)
                .execute(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;
            }
            Err(e) => {
                // F: transient errors retry with a counter; after
                // MAX_RETRY_ATTEMPTS the request is marked failed with the
                // reason recorded (never silently rejected).
                let attempt = self.read_retry_attempt(request_id).await + 1;
                let decision = next_retry_decision(attempt);
                let retry_state = serde_json::json!({
                    "retry_attempt": decision.attempt,
                    "error": e,
                });
                match decision.status {
                    RetryStatus::Retrying => {
                        warn!(request_id, attempt, error = %e, "GDPR request processing failed — retrying");
                        sqlx::query(
                            "UPDATE data_subject_requests
                             SET status = 'retrying', completed_at = NULL, result = $2
                             WHERE id = $1",
                        )
                        .bind(request_id)
                        .bind(&retry_state)
                        .execute(&self.db)
                        .await
                        .map_err(|e| format!("DB error updating GDPR status to retrying: {e}"))?;
                        // Requeue for the next worker pass. Once the retry
                        // state is durably recorded, report Ok so the queue
                        // worker can ack the entry (Err is reserved for
                        // "outcome not recorded" — those entries stay for
                        // the recovery sweep).
                        self.enqueue_request(request_id).await?;
                        return Ok(DataSubjectRequestResult {
                            data: Some(retry_state),
                            export_url: None,
                            export_expires_at: None,
                            deleted_records: None,
                            deletion_confirmation: None,
                            modified_records: None,
                            rejection_reason: None,
                            partial: None,
                            review_required: false,
                            retained_disclosure: None,
                        });
                    }
                    RetryStatus::Failed => {
                        warn!(request_id, attempt, error = %e, "GDPR request processing failed — retries exhausted");
                        sqlx::query(
                            "UPDATE data_subject_requests
                             SET status = 'failed', completed_at = NOW(), result = $2
                             WHERE id = $1",
                        )
                        .bind(request_id)
                        .bind(&retry_state)
                        .execute(&self.db)
                        .await
                        .map_err(|e| format!("DB error updating GDPR status to failed: {e}"))?;
                        return Ok(DataSubjectRequestResult {
                            data: Some(retry_state),
                            export_url: None,
                            export_expires_at: None,
                            deleted_records: None,
                            deletion_confirmation: None,
                            modified_records: None,
                            rejection_reason: None,
                            partial: None,
                            review_required: false,
                            retained_disclosure: None,
                        });
                    }
                }
            }
        }

        result
    }

    /// Read the retry attempt counter stored in the request's result JSONB.
    async fn read_retry_attempt(&self, request_id: &str) -> u32 {
        let attempt: Option<String> = sqlx::query_scalar(
            "SELECT result->>'retry_attempt' FROM data_subject_requests WHERE id = $1",
        )
        .bind(request_id)
        .fetch_optional(&self.db)
        .await
        .ok()
        .flatten();
        attempt.and_then(|a| a.parse().ok()).unwrap_or(0)
    }

    // ── Access Request (Article 15) ────────────────────────

    async fn process_access_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        let mut data = serde_json::Map::new();
        let email = &request.email;
        let tid = &request.tenant_id;
        let mut stores: Vec<StoreExportResult> = Vec::new();

        // Collect contact profile — `contacts` is the canonical subscriber
        // store (migration 068/075); the old `subscribers` read targeted a
        // table that exists only in test fixtures.
        self.export_table(
            &mut data,
            &mut stores,
            "contacts",
            "SELECT row_to_json(c) FROM contacts c
             WHERE tenant_id = $2 AND LOWER(email) = LOWER($1)",
            email,
            tid,
        )
        .await?;

        // Collect event history from the canonical `events` store
        // (migration 075). M-04: configurable limit, G: explicit truncation
        // flag in the manifest when the cap is hit.
        let history: Result<Vec<(serde_json::Value,)>, sqlx::Error> = sqlx::query_as(
            "SELECT row_to_json(e) FROM events e
             WHERE tenant_id = $2 AND LOWER(recipient) = LOWER($1)
             ORDER BY timestamp DESC LIMIT $3",
        )
        .bind(email)
        .bind(tid)
        .bind(self.config.access_request_max_messages)
        .fetch_all(&self.db)
        .await;
        let mut truncated = false;
        match history {
            Ok(rows) => {
                truncated = rows.len() as i64 >= self.config.access_request_max_messages;
                let events: Vec<serde_json::Value> = rows.into_iter().map(|(v,)| v).collect();
                stores.push(StoreExportResult::included("events", events.len()));
                data.insert("events".into(), serde_json::Value::Array(events));
            }
            Err(e) if is_missing_store(&e) => {
                stores.push(StoreExportResult::skipped("events", &e));
            }
            Err(e) => return Err(format!("DB error (events): {e}")),
        }

        // Message content the subject sent or received (canonical `messages`
        // store): from/to/cc/bcc JSONB recipient arrays.
        self.export_table(
            &mut data,
            &mut stores,
            "messages",
            "SELECT row_to_json(m) FROM messages m
             WHERE tenant_id = $2 AND (
               LOWER(from_email) = LOWER($1)
               OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(
                            COALESCE(to_emails, '[]'::jsonb) || COALESCE(cc_emails, '[]'::jsonb) ||
                            COALESCE(bcc_emails, '[]'::jsonb)) AS r(addr)
                          WHERE LOWER(addr) = LOWER($1))
             )",
            email,
            tid,
        )
        .await?;

        // The subject's user account (anonymized-readable fields —
        // sanitize_pii strips password_hash/mfa_secret before storage).
        let user_rows: Result<Vec<(serde_json::Value,)>, sqlx::Error> = sqlx::query_as(
            "SELECT row_to_json(u) FROM users u WHERE tenant_id = $2 AND LOWER(email) = LOWER($1)",
        )
        .bind(email)
        .bind(tid)
        .fetch_all(&self.db)
        .await;
        match user_rows {
            Ok(rows) => {
                let vals: Vec<serde_json::Value> =
                    rows.into_iter().map(|(v,)| sanitize_pii(v)).collect();
                stores.push(StoreExportResult::included("users", vals.len()));
                data.insert("users".into(), serde_json::Value::Array(vals));
            }
            Err(e) if is_missing_store(&e) => {
                stores.push(StoreExportResult::skipped("users", &e));
            }
            Err(e) => return Err(format!("DB error (users): {e}")),
        }

        // Collect consent records
        let consents: Result<Vec<(serde_json::Value,)>, sqlx::Error> = sqlx::query_as(
            "SELECT row_to_json(c) FROM consent_records c
             WHERE tenant_id = $2 AND LOWER(email) = LOWER($1)",
        )
        .bind(email)
        .bind(tid)
        .fetch_all(&self.db)
        .await;
        match consents {
            Ok(rows) => {
                let vals: Vec<serde_json::Value> = rows.into_iter().map(|(v,)| v).collect();
                stores.push(StoreExportResult::included("consent_records", vals.len()));
                data.insert("consents".into(), serde_json::Value::Array(vals));
            }
            Err(e) if is_missing_store(&e) => {
                stores.push(StoreExportResult::skipped("consent_records", &e));
            }
            Err(e) => return Err(format!("DB error (consent_records): {e}")),
        }

        // Double-opt-in tokens pending for the subject.
        self.export_table(
            &mut data,
            &mut stores,
            "double_opt_in_tokens",
            "SELECT row_to_json(d) FROM double_opt_in_tokens d
             WHERE tenant_id = $2 AND LOWER(email) = LOWER($1)",
            email,
            tid,
        )
        .await?;

        // Past SAR exports for the subject.
        self.export_table(
            &mut data,
            &mut stores,
            "gdpr_exports",
            "SELECT row_to_json(g) FROM gdpr_exports g
             WHERE tenant_id = $2 AND LOWER(email) = LOWER($1)",
            email,
            tid,
        )
        .await?;

        // The subject's active sessions (device/IP accountability trail).
        self.export_table(
            &mut data,
            &mut stores,
            "sessions",
            "SELECT row_to_json(s) FROM sessions s
             WHERE tenant_id = $2 AND user_id IN \
               (SELECT id::text FROM users WHERE LOWER(email) = LOWER($1))",
            email,
            tid,
        )
        .await?;

        // The subject's suppression entries (opt-out records)
        self.export_table(
            &mut data,
            &mut stores,
            "suppression_list",
            "SELECT row_to_json(s) FROM suppression_list s
             WHERE tenant_id = $2 AND LOWER(email) = LOWER($1)",
            email,
            tid,
        )
        .await?;

        // List memberships (kept aligned with the erasure map; absent from
        // the canonical chain today → honestly reported as skipped).
        self.export_table(
            &mut data,
            &mut stores,
            "contact_list_members",
            "SELECT row_to_json(m) FROM contact_list_members m
             WHERE tenant_id = $2 AND LOWER(subscriber_email) = LOWER($1)",
            email,
            tid,
        )
        .await?;

        // Invoices — retained for statutory reasons; export an anonymized
        // view (subject PII textually replaced with a redaction marker).
        //
        // F82: subject ownership is resolved through the CANONICAL invoice
        // identity — the immutable billing-address snapshot's email and the
        // customer/tenant identity relation (the subject being a user of the
        // invoice's tenant). There is no customer_email column; querying it
        // failed with 42703 and the old handler misclassified that schema
        // error as an optional-store skip, silently dropping the subject's
        // invoices from the export. The snapshot text is parsed in Rust so a
        // malformed legacy snapshot can never abort the whole export with a
        // JSON cast error. Invoices are a REQUIRED canonical store: any
        // error (including 42P01/42703) fails the export visibly and the
        // request keeps its retry work instead of reporting a partial skip.
        let subject_is_tenant_user: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users u              WHERE u.tenant_id::text = $1 AND LOWER(u.email) = LOWER($2))",
        )
        .bind(tid)
        .bind(email)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("DB error (invoices identity): {e}"))?;

        let invoice_rows: Result<Vec<(serde_json::Value, Option<String>)>, sqlx::Error> =
            sqlx::query_as(
                "SELECT row_to_json(i), i.billing_address FROM invoices i WHERE tenant_id = $1",
            )
            .bind(tid)
            .fetch_all(&self.db)
            .await;
        match invoice_rows {
            Ok(rows) => {
                let marker = redact_marker(email);
                let email_lower = email.to_lowercase();
                let mut vals: Vec<serde_json::Value> = Vec::with_capacity(rows.len());
                for (row, snapshot_raw) in rows {
                    let snapshot_email_matches = snapshot_raw
                        .as_deref()
                        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                        .and_then(|snap| {
                            snap.get("email")
                                .and_then(|v| v.as_str())
                                .map(str::to_string)
                        })
                        .is_some_and(|snap_email| snap_email.to_lowercase() == email_lower);
                    if subject_is_tenant_user || snapshot_email_matches {
                        vals.push(anonymize_json_text(row, email, &marker));
                    }
                }
                stores.push(StoreExportResult::included("invoices", vals.len()));
                data.insert("invoices".into(), serde_json::Value::Array(vals));
            }
            // F82: REQUIRED store — a schema error is NOT an optional-store
            // skip. Failing keeps the request's retry work; the export is
            // visibly incomplete rather than quietly missing invoices.
            Err(e) => return Err(format!("DB error (invoices): {e}")),
        }

        // Audit entries referencing the subject (accountability trail).
        self.export_table(
            &mut data,
            &mut stores,
            "audit_logs",
            "SELECT row_to_json(a) FROM audit_logs a
             WHERE tenant_id = $2
               AND (user_id = $1 OR resource_id = $1 OR details->>'email' = $1)
             LIMIT 1000",
            email,
            tid,
        )
        .await?;

        // Tenant-owned resources carry no personal data of the subject —
        // listed in the manifest for transparency, never queried. The
        // ClickHouse analytics store is declared as not-exportable here
        // (F9: the erasure side does purge it best-effort).
        stores.push(StoreExportResult::not_subject_data("api_keys"));
        stores.push(StoreExportResult::not_subject_data("webhooks"));
        stores.push(StoreExportResult::not_exportable("clickhouse_events"));

        // G: explicit manifest — per-store status plus truncation flag.
        let manifest = build_export_manifest(&stores, truncated);
        let partial = stores
            .iter()
            .any(|s| matches!(s.status, ExportStoreStatus::SkippedMissing));
        data.insert("manifest".into(), manifest);

        // Store export. NOTE: `data` is JSONB — the value must be bound as a
        // serde_json::Value (JSONB oid). Binding the pretty-printed String
        // sends a TEXT parameter, which Postgres rejects with
        // "column data is of type jsonb but expression is of type text".
        let export_value = serde_json::Value::Object(data.clone());

        let export_id = Uuid::new_v4().to_string();
        let export_expires = Utc::now() + Duration::days(self.config.export_expiration_days);
        let export_url = format!("{}/gdpr/exports/{}", self.config.export_base_url, export_id);

        sqlx::query(
            "INSERT INTO gdpr_exports (id, request_id, tenant_id, email, data, export_url, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())",
        )
        .bind(&export_id)
        .bind(&request.id)
        .bind(tid)
        .bind(email)
        .bind(&export_value)
        .bind(&export_url)
        .bind(export_expires)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        info!(request_id = %request.id, partial, truncated, "Access request processed");
        Ok(DataSubjectRequestResult {
            data: Some(serde_json::Value::Object(data)),
            export_url: Some(export_url),
            export_expires_at: Some(export_expires),
            deleted_records: None,
            deletion_confirmation: None,
            modified_records: None,
            rejection_reason: None,
            partial: Some(partial),
            review_required: false,
            retained_disclosure: None,
        })
    }

    /// Fetch an access-export table into `data` under its own key, recording
    /// the per-store outcome. Missing stores are recorded as skipped; other
    /// errors abort the export (an incomplete export must not look complete).
    /// The SQL must use `$1` = subject email and `$2` = tenant id.
    async fn export_table(
        &self,
        data: &mut serde_json::Map<String, serde_json::Value>,
        stores: &mut Vec<StoreExportResult>,
        store: &'static str,
        sql: &str,
        email: &str,
        tenant_id: &str,
    ) -> Result<(), String> {
        let rows: Result<Vec<(serde_json::Value,)>, sqlx::Error> = sqlx::query_as(sql)
            .bind(email)
            .bind(tenant_id)
            .fetch_all(&self.db)
            .await;
        match rows {
            Ok(rows) => {
                let vals: Vec<serde_json::Value> = rows.into_iter().map(|(v,)| v).collect();
                stores.push(StoreExportResult::included(store, vals.len()));
                data.insert(store.into(), serde_json::Value::Array(vals));
            }
            Err(e) if is_missing_store(&e) => {
                stores.push(StoreExportResult::skipped(store, &e));
            }
            Err(e) => return Err(format!("DB error ({store}): {e}")),
        }
        Ok(())
    }

    // ── Erasure Request (Article 17) ───────────────────────

    async fn process_erasure_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        // A statutory-retention decision (invoices) needs the retention-class
        // registry; seed it idempotently before any store evaluates it.
        // Without the registry the erasure must fail loudly rather than guess
        // that a statutory record is deletable.
        retention_classes::ensure_seeded(&self.db)
            .await
            .map_err(|e| format!("retention class registry unavailable: {e}"))?;

        let stores = erasure_stores();
        let mut results = Vec::with_capacity(stores.len());

        for store in stores {
            let result = self.erase_store(request, store).await;
            let failed = matches!(result.status, StoreErasureStatus::Failed);
            results.push(result);
            if failed {
                // Collect all outcomes for the error report, then fail loudly —
                // never claim success while a store failed (audit finding B).
                let failed_stores: Vec<&str> = results
                    .iter()
                    .filter(|r| matches!(r.status, StoreErasureStatus::Failed))
                    .map(|r| r.store)
                    .collect();
                return Err(format!("erasure failed for data stores: {failed_stores:?}"));
            }
        }

        // Clear subject-scoped Redis keys (a failure here is also a hard error —
        // the cached PII would survive the "completed" erasure).
        self.clear_redis_keys(&request.tenant_id, &request.email)
            .await?;

        let total_deleted: u64 = results.iter().map(|r| r.rows_affected).sum();
        let partial = matches!(
            summarize_erasure(&results),
            ErasureOverall::Partial | ErasureOverall::Failed
        );
        // Art. 17 + statutory retention: the result DISCLOSES what was kept
        // because an independent legal obligation (Estonian accounting
        // evidence, seven years) outranks an ordinary account erasure — with
        // the reason and the exact date it may be deleted.
        let retained =
            legal_archive::disclosure_for_subject(&self.db, &request.tenant_id, &request.email)
                .await
                .map_err(|e| format!("DB error reading retention disclosure: {e}"))?;
        let disclosure = if retained.is_empty() {
            None
        } else {
            Some(serde_json::json!({
                "policy": "Records with an independent statutory retention obligation \
                           (Estonian accounting evidence, seven years) are not deleted by an \
                           ordinary erasure. They were redacted of the subject's data and moved \
                           to the legally-restricted archive until the statutory expiry, after \
                           which they are deleted.",
                "retained": retained,
            }))
        };

        let mut confirmation =
            build_deletion_confirmation(&request.id, &request.tenant_id, &request.email, &results);
        if let Some(disclosure) = &disclosure {
            if let Some(obj) = confirmation.as_object_mut() {
                obj.insert("retained_disclosure".into(), disclosure.clone());
                obj.insert(
                    "confirmation".into(),
                    serde_json::json!(
                        "All in-scope personal data has been erased or anonymized as detailed per \
                         store, per GDPR Article 17. Records listed under retained_disclosure are \
                         kept under an independent statutory retention obligation and will be \
                         deleted at the stated expiry."
                    ),
                );
            }
        }

        info!(request_id = %request.id, records = total_deleted, partial, retained = retained.len(), "Erasure request processed");
        Ok(DataSubjectRequestResult {
            data: None,
            export_url: None,
            export_expires_at: None,
            deleted_records: Some(total_deleted as i64),
            deletion_confirmation: Some(confirmation),
            modified_records: None,
            rejection_reason: None,
            partial: Some(partial),
            review_required: false,
            retained_disclosure: disclosure,
        })
    }

    /// Execute one store's erasure action, scoped strictly to the data subject.
    /// Missing optional tables are reported as skipped (deployment without
    /// that store); genuine errors are reported as failures.
    pub async fn erase_store(
        &self,
        request: &DataSubjectRequest,
        store: ErasureStore,
    ) -> StoreErasureResult {
        use ErasureStore::*;
        let tid = &request.tenant_id;
        let email = &request.email;
        // Anonymize variants report `anonymized`, not `deleted`.
        let expect_anonymized = matches!(
            store,
            AnonymizeMessageContent | AnonymizeUserTombstone | AnonymizeInvoiceSnapshot { .. }
        );

        let result: Result<u64, sqlx::Error> = match store {
            TableBySubjectEmail {
                name: _,
                table,
                email_column,
            } => sqlx::query(&format!(
                // LOWER() on both sides: writers across the platform are
                // inconsistent about email case (some normalize on write,
                // some do not), and an exact-match DELETE silently MISSES
                // User@Example.com rows for a user@example.com DSR while
                // still reporting success — the deletion certificate then
                // attests PII is gone that is not.
                "DELETE FROM {table} WHERE tenant_id = $1 AND LOWER({email_column}) = LOWER($2)"
            ))
            .bind(tid)
            .bind(email)
            .execute(&self.db)
            .await
            .map(|r| r.rows_affected()),
            AiChatByUserEmail => {
                // ai_chat_messages.user_id is the callers' user identifier;
                // resolve via the users row (pre-tombstone, same as sessions).
                let res = sqlx::query(
                    "DELETE FROM ai_chat_messages WHERE user_id IN \
                     (SELECT id::text FROM users WHERE LOWER(email) = LOWER($1))",
                )
                .bind(email)
                .execute(&self.db)
                .await;
                return match res {
                    Ok(r) => StoreErasureResult {
                        store: store.name(),
                        status: StoreErasureStatus::Deleted,
                        rows_affected: r.rows_affected(),
                        error: None,
                    },
                    Err(e) if is_missing_table(&e) => StoreErasureResult {
                        store: store.name(),
                        status: StoreErasureStatus::SkippedMissingTable,
                        rows_affected: 0,
                        error: None,
                    },
                    Err(e) => StoreErasureResult {
                        store: store.name(),
                        status: StoreErasureStatus::BestEffortFailed,
                        rows_affected: 0,
                        error: Some(e.to_string()),
                    },
                };
            }
            SessionsByUserEmail => {
                // users.id is UUID while sessions.user_id is TEXT — cast to
                // text or Postgres rejects the IN-subquery (uuid = text has
                // no operator).
                sqlx::query(
                    "DELETE FROM sessions WHERE user_id IN \
                     (SELECT id::text FROM users WHERE LOWER(email) = LOWER($1))",
                )
                .bind(email)
                .execute(&self.db)
                .await
                .map(|r| r.rows_affected())
            }
            AnonymizeInvoiceSnapshot { name: _ } => {
                // F82: redact the subject's email inside the immutable
                // billing-address snapshot JSON. The snapshot text is
                // parsed/serialized in Rust (a malformed legacy snapshot is
                // skipped, never a SQL JSON-cast abort), and only snapshots
                // actually addressed to the subject are rewritten. The
                // financial record itself is RETAINED (statutory).
                let email_lower = email.to_lowercase();
                let rows: Vec<(String, Option<String>, DateTime<Utc>)> = match sqlx::query_as(
                    "SELECT id::text, billing_address, COALESCE(issued_at, created_at) \
                     FROM invoices WHERE tenant_id = $1",
                )
                .bind(tid)
                .fetch_all(&self.db)
                .await
                {
                    Ok(rows) => rows,
                    // F82: invoices are a REQUIRED canonical store — a
                    // schema error fails the erasure visibly; it is not an
                    // optional-store skip.
                    Err(e) => {
                        return StoreErasureResult {
                            store: store.name(),
                            status: StoreErasureStatus::Failed,
                            rows_affected: 0,
                            error: Some(format!("required store: {e}")),
                        };
                    }
                };

                // The statutory accounting class grounds the retention: no
                // registry entry, no retention decision (fail loudly). Seed
                // the catalogue idempotently so a store-level call is
                // self-sufficient too (the full erasure seeds once up front).
                if let Err(e) = retention_classes::ensure_seeded(&self.db).await {
                    return StoreErasureResult {
                        store: store.name(),
                        status: StoreErasureStatus::Failed,
                        rows_affected: 0,
                        error: Some(format!("statutory retention registry unavailable: {e}")),
                    };
                }
                let class = match retention_classes::statutory_accounting_class(&self.db).await {
                    Ok(class) => class,
                    Err(e) => {
                        return StoreErasureResult {
                            store: store.name(),
                            status: StoreErasureStatus::Failed,
                            rows_affected: 0,
                            error: Some(format!("statutory retention registry: {e}")),
                        };
                    }
                };

                let marker = redact_marker(email);
                let subject_hash = legal_archive::subject_email_hash(email);
                let mut updated: u64 = 0;
                let mut failure: Option<sqlx::Error> = None;
                for (invoice_id, snapshot_raw, issued_at) in rows {
                    let Some(raw) = snapshot_raw.as_deref() else {
                        continue;
                    };
                    let Ok(mut snapshot) = serde_json::from_str::<serde_json::Value>(raw) else {
                        continue; // malformed legacy snapshot: skip safely
                    };
                    let matches_subject = snapshot
                        .get("email")
                        .and_then(|v| v.as_str())
                        .is_some_and(|e| e.to_lowercase() == email_lower);
                    if !matches_subject {
                        continue;
                    }
                    if let Some(obj) = snapshot.as_object_mut() {
                        obj.insert("email".into(), serde_json::Value::String(marker.clone()));
                    }
                    match sqlx::query(
                        "UPDATE invoices SET billing_address = $2, updated_at = NOW() \
                         WHERE id::text = $1",
                    )
                    .bind(&invoice_id)
                    .bind(snapshot.to_string())
                    .execute(&self.db)
                    .await
                    {
                        Ok(r) => updated += r.rows_affected(),
                        Err(e) => {
                            failure = Some(e);
                            break;
                        }
                    }

                    // product-active → legally-restricted archive: the record
                    // survives, its subject data is redacted, and the archive
                    // row records why and until when.
                    let expiry = class.expiry_for(issued_at);
                    let disclosure = serde_json::json!({
                        "source_table": "invoices",
                        "record_id": invoice_id,
                        "retention_class_id": class.id,
                        "legal_reference": class.legal_basis_reference,
                        "reason": "Statutory accounting retention (EE, seven years): the \
                                   invoice is retained as accounting evidence after the \
                                   subject's erasure; the subject's PII was redacted.",
                        "retain_until": expiry.to_rfc3339(),
                    });
                    let input = legal_archive::ArchiveRecordInput {
                        tenant_id: tid.clone(),
                        subject_email_hash: subject_hash.clone(),
                        source_table: "invoices".into(),
                        source_record_id: invoice_id.clone(),
                        retention_class_id: class.id.clone(),
                        reason: "Statutory accounting retention (EE, seven years) — Art. 17(3)(b) \
                                 legal obligation"
                            .into(),
                        statutory_expiry_at: expiry,
                        disclosure,
                    };
                    if let Err(e) = legal_archive::archive_record(&self.db, &input).await {
                        failure = Some(sqlx::Error::Protocol(e));
                        break;
                    }
                }
                if let Some(e) = failure {
                    return StoreErasureResult {
                        store: store.name(),
                        status: StoreErasureStatus::Failed,
                        rows_affected: 0,
                        error: Some(e.to_string()),
                    };
                }
                return StoreErasureResult {
                    store: store.name(),
                    status: StoreErasureStatus::Anonymized,
                    rows_affected: updated,
                    error: None,
                };
            }
            AnonymizeSubjectEmail {
                name: _,
                table,
                columns,
            } => {
                // A-3: statutory retention — redact the subject's PII in
                // email-bearing columns instead of deleting the rows.
                let marker = redact_marker(email);
                let mut updated: u64 = 0;
                let mut found_any = false;
                let mut failure: Option<sqlx::Error> = None;
                for col in columns {
                    let sql = format!(
                        "UPDATE {table} SET {col} = $3 WHERE tenant_id = $1 AND LOWER({col}) = LOWER($2)"
                    );
                    match sqlx::query(&sql)
                        .bind(tid)
                        .bind(email)
                        .bind(&marker)
                        .execute(&self.db)
                        .await
                    {
                        Ok(r) => {
                            found_any = true;
                            updated += r.rows_affected();
                        }
                        Err(e) if is_missing_store(&e) => { /* column absent */ }
                        Err(e) => {
                            failure = Some(e);
                            break;
                        }
                    }
                }
                if let Some(e) = failure {
                    return StoreErasureResult {
                        store: store.name(),
                        status: StoreErasureStatus::Failed,
                        rows_affected: 0,
                        error: Some(e.to_string()),
                    };
                }
                return StoreErasureResult {
                    store: store.name(),
                    status: if found_any {
                        StoreErasureStatus::Anonymized
                    } else {
                        StoreErasureStatus::SkippedMissingTable
                    },
                    rows_affected: updated,
                    error: None,
                };
            }
            AnonymizeMessageContent => {
                // F1: canonical messages store (073). Redact the subject's
                // copy of every send they were part of — recipient arrays,
                // subject line and bodies — while keeping the row (statutory
                // sending record; other recipients' data lives in it too).
                let marker = redact_marker(email);
                let marker_json =
                    serde_json::Value::Array(vec![serde_json::Value::String(marker.clone())]);
                sqlx::query(
                    "UPDATE messages SET
                       from_email = CASE WHEN LOWER(from_email) = LOWER($2) THEN $3 ELSE from_email END,
                       to_emails = $4::jsonb,
                       cc_emails = CASE WHEN cc_emails IS NULL THEN NULL ELSE $4::jsonb END,
                       bcc_emails = CASE WHEN bcc_emails IS NULL THEN NULL ELSE $4::jsonb END,
                       subject = $3,
                       html_body = NULL,
                       text_body = NULL
                     WHERE tenant_id = $1 AND (
                       LOWER(from_email) = LOWER($2)
                       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(
                                    COALESCE(to_emails, '[]'::jsonb) || COALESCE(cc_emails, '[]'::jsonb) ||
                                    COALESCE(bcc_emails, '[]'::jsonb)) AS r(addr)
                                  WHERE LOWER(addr) = LOWER($2))
                     )",
                )
                .bind(tid)
                .bind(email)
                .bind(&marker)
                .bind(&marker_json)
                .execute(&self.db)
                .await
                .map(|r| r.rows_affected())
            }
            AnonymizeUserTombstone => {
                // F1/F9: keep a tombstone row (Art. 17 hygiene) with every
                // PII field redacted. The marker embeds the tenant so the
                // globally-UNIQUE users.email never collides when the same
                // subject is erased in two tenants.
                let marker = user_tombstone_marker(email, tid);
                sqlx::query(
                    "UPDATE users SET
                       email = $3,
                       name = NULL,
                       password_hash = 'ERASED',
                       mfa_secret = NULL,
                       status = 'erased'
                     WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
                )
                .bind(tid)
                .bind(email)
                .bind(&marker)
                .execute(&self.db)
                .await
                .map(|r| r.rows_affected())
            }
            ClickHouseEvents => {
                // F1: real PII store. Config-gated best-effort
                // `ALTER TABLE events DELETE WHERE recipient = ...` over the
                // ClickHouse HTTP interface (same env contract as the
                // analytics crate's client).
                return self.erase_clickhouse_events(email).await;
            }
            Retained { name: _, reason } => {
                // Statutory / tenant-owned data: intentionally NOT deleted.
                return StoreErasureResult {
                    store: store.name(),
                    status: StoreErasureStatus::Retained(reason),
                    rows_affected: 0,
                    error: None,
                };
            }
        };

        match result {
            Ok(rows) => StoreErasureResult {
                store: store.name(),
                status: if expect_anonymized {
                    StoreErasureStatus::Anonymized
                } else {
                    StoreErasureStatus::Deleted
                },
                rows_affected: rows,
                error: None,
            },
            Err(e) => {
                let status = if is_missing_table(&e) {
                    StoreErasureStatus::SkippedMissingTable
                } else {
                    StoreErasureStatus::Failed
                };
                if status == StoreErasureStatus::Failed {
                    tracing::error!(
                        store = store.name(),
                        error = %e,
                        "Erasure store failure"
                    );
                } else {
                    warn!(
                        store = store.name(),
                        "Erasure store absent in this deployment — skipped"
                    );
                }
                StoreErasureResult {
                    store: store.name(),
                    status,
                    rows_affected: 0,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// F1: best-effort ClickHouse purge of the subject's analytics events.
    ///
    /// `ALTER TABLE events DELETE WHERE recipient = '<email>'` is an async
    /// mutation — a 200 response means submitted, not yet applied, so the
    /// certificate says `mutation_submitted`. Failures are recorded as
    /// `best_effort_failed` (the Postgres erasure must not fail because an
    /// analytics node is down), and a disabled configuration is reported as
    /// `skipped_not_configured` rather than silently omitted.
    async fn erase_clickhouse_events(&self, email: &str) -> StoreErasureResult {
        if !self.config.clickhouse_erasure_enabled {
            return StoreErasureResult {
                store: "clickhouse_events",
                status: StoreErasureStatus::SkippedNotConfigured,
                rows_affected: 0,
                error: None,
            };
        }
        // Escape single quotes/backslashes for the ClickHouse SQL literal.
        let escaped = email.replace('\\', "\\\\").replace('\'', "\\'");
        let statement = format!(
            "ALTER TABLE {}.events DELETE WHERE lower(recipient) = lower('{}')",
            self.config.clickhouse_database, escaped
        );
        let url = format!("{}/", self.config.clickhouse_url.trim_end_matches('/'));
        let response = reqwest::Client::new()
            .post(&url)
            .basic_auth(
                &self.config.clickhouse_user,
                Some(&self.config.clickhouse_password),
            )
            .timeout(std::time::Duration::from_secs(15))
            .query(&[("query", statement.as_str())])
            .send()
            .await
            .and_then(|r| r.error_for_status());

        match response {
            Ok(_) => {
                info!("ClickHouse erasure mutation submitted for a data subject");
                StoreErasureResult {
                    store: "clickhouse_events",
                    status: StoreErasureStatus::MutationSubmitted,
                    rows_affected: 0,
                    error: None,
                }
            }
            Err(e) => {
                warn!(error = %e, "ClickHouse erasure mutation failed (best-effort)");
                StoreErasureResult {
                    store: "clickhouse_events",
                    status: StoreErasureStatus::BestEffortFailed,
                    rows_affected: 0,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    // ── Portability Request (Article 20) ───────────────────

    async fn process_portability_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        // Portability = access export in machine-readable format
        self.process_access_request(request).await
    }

    // ── Rectification (Article 16) ─────────────────────────

    async fn process_rectification_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        // F: Rectification (Art. 16) alters data and requires human review of
        // the requested corrections. It must never be auto-completed with
        // "0 records modified" — the request parks in pending_manual_review
        // (set by process_request) until an operator applies the changes.
        info!(request_id = %request.id, "Rectification request queued for manual review");
        Ok(DataSubjectRequestResult {
            data: None,
            export_url: None,
            export_expires_at: None,
            deleted_records: None,
            deletion_confirmation: None,
            modified_records: Some(0),
            rejection_reason: None,
            partial: None,
            review_required: true,
            retained_disclosure: None,
        })
    }

    // ── Restriction of Processing (Article 18) ────────────

    async fn process_restriction_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        // Add to suppression list to prevent future processing
        sqlx::query(
            "INSERT INTO suppression_list (id, tenant_id, email, reason, created_at)
             VALUES ($1, $2, $3, 'gdpr_restriction', NOW())
             ON CONFLICT (tenant_id, email) DO UPDATE SET reason = 'gdpr_restriction'",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&request.tenant_id)
        .bind(&request.email)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        info!(request_id = %request.id, "Restriction request completed");
        Ok(DataSubjectRequestResult {
            data: None,
            export_url: None,
            export_expires_at: None,
            deleted_records: None,
            deletion_confirmation: None,
            modified_records: Some(1),
            rejection_reason: None,
            partial: None,
            review_required: false,
            retained_disclosure: None,
        })
    }

    // ── Objection (Article 21) ────────────────────────────

    async fn process_objection_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectRequestResult, String> {
        // Similar to restriction — suppress + withdraw consents
        let mut tx = self.db.begin().await.map_err(|e| format!("DB: {e}"))?;

        let r = sqlx::query(
            "UPDATE consent_records SET granted = false, revoked_at = NOW()
             WHERE email = $1 AND tenant_id = $2 AND granted = true",
        )
        .bind(&request.email)
        .bind(&request.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        sqlx::query(
            "INSERT INTO suppression_list (id, tenant_id, email, reason, created_at)
             VALUES ($1, $2, $3, 'gdpr_objection', NOW())
             ON CONFLICT (tenant_id, email) DO UPDATE SET reason = 'gdpr_objection'",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&request.tenant_id)
        .bind(&request.email)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        tx.commit().await.map_err(|e| format!("DB: {e}"))?;

        info!(request_id = %request.id, affected = r.rows_affected(), "Objection request completed");
        Ok(DataSubjectRequestResult {
            data: None,
            export_url: None,
            export_expires_at: None,
            deleted_records: None,
            deletion_confirmation: None,
            modified_records: Some(r.rows_affected() as i64),
            rejection_reason: None,
            partial: None,
            review_required: false,
            retained_disclosure: None,
        })
    }

    // ── Consent Management ────────────────────────────────

    /// Record or update a consent. If consent_type is marketing and granted=false,
    /// cascade to analytics and profiling.
    #[allow(clippy::too_many_arguments)]
    pub fn record_consent<'a>(
        &'a self,
        tenant_id: &'a str,
        subscriber_id: &'a str,
        email: &'a str,
        consent_type: ConsentType,
        granted: bool,
        source: ConsentSource,
        ip_address: Option<&'a str>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ConsentRecord, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();
            let granted_at = if granted { Some(now) } else { None };
            let revoked_at = if granted { None } else { Some(now) };
            let expires_at = if granted {
                Some(now + Duration::days(self.config.data_retention_days))
            } else {
                None
            };

            // H: RETURNING id — on re-consent the upsert updates the existing
            // row, so the freshly generated `id` above does NOT match any row.
            // All follow-up writes (proof document) must target the returned id.
            let id: String = sqlx::query_scalar(
                "INSERT INTO consent_records
               (id, tenant_id, subscriber_id, email, consent_type, granted,
                granted_at, revoked_at, source, ip_address, expires_at, metadata)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'{}'::jsonb)
             ON CONFLICT (tenant_id, subscriber_id, consent_type) DO UPDATE SET
               granted = EXCLUDED.granted,
               source = EXCLUDED.source,
               ip_address = EXCLUDED.ip_address,
               granted_at = CASE WHEN EXCLUDED.granted THEN EXCLUDED.granted_at
                                 ELSE consent_records.granted_at END,
               revoked_at = CASE WHEN NOT EXCLUDED.granted THEN NOW() ELSE NULL END,
               expires_at = EXCLUDED.expires_at
             RETURNING id",
            )
            .bind(&id)
            .bind(tenant_id)
            .bind(subscriber_id)
            .bind(email)
            .bind(consent_type.to_string())
            .bind(granted)
            .bind(granted_at)
            .bind(revoked_at)
            .bind(source.to_string())
            .bind(ip_address)
            .bind(expires_at)
            .fetch_one(&self.db)
            .await
            .map_err(|e| format!("DB: {e}"))?;

            // Marketing cascade:withdrawing marketing also withdraws analytics + profiling
            if !granted && consent_type == ConsentType::Marketing {
                for cascade_type in &[ConsentType::Analytics, ConsentType::Profiling] {
                    if let Err(e) = self
                        .record_consent(
                            tenant_id,
                            subscriber_id,
                            email,
                            *cascade_type,
                            false,
                            ConsentSource::System,
                            ip_address,
                        )
                        .await
                    {
                        tracing::error!(
                            error = %e,
                            tenant_id = %tenant_id,
                            email = %mail_common::pii::redact_email(email),
                            cascade_type = %cascade_type,
                            "GDPR VIOLATION: Failed to cascade consent withdrawal — manual intervention required"
                        );
                        return Err(format!(
                            "Failed to cascade {cascade_type} consent withdrawal: {e}"
                        ));
                    }
                }
            }

            // Generate and store consent certificate (proof document)
            let certificate_json = build_consent_certificate(
                &self.config.consent_signing_key,
                &id,
                tenant_id,
                subscriber_id,
                email,
                &consent_type.to_string(),
                granted,
                granted_at,
                revoked_at,
                &source.to_string(),
                ip_address,
            )?;

            sqlx::query("UPDATE consent_records SET proof_document = $1 WHERE id = $2")
                .bind(&certificate_json)
                .bind(&id)
                .execute(&self.db)
                .await
                .map_err(|e| format!("DB error storing proof document: {e}"))?;

            let record = ConsentRecord {
                id,
                tenant_id: tenant_id.into(),
                subscriber_id: subscriber_id.into(),
                email: email.into(),
                consent_type,
                granted,
                granted_at,
                revoked_at,
                source,
                ip_address: ip_address.map(String::from),
                user_agent: None,
                proof_document: Some(certificate_json),
                expires_at,
                metadata: serde_json::json!({}),
            };

            info!(
                %tenant_id, %subscriber_id, %consent_type,
                %granted, "Consent recorded"
            );
            Ok(record)
        }) // Box::pin
    }

    /// Initiate double opt-in:store pending consent + return token.
    pub async fn initiate_double_opt_in(
        &self,
        tenant_id: &str,
        subscriber_id: &str,
        consent_type: ConsentType,
        email: &str,
    ) -> Result<String, String> {
        let token = Uuid::new_v4().to_string();
        let token_hash = sha256_hex(&token);
        let expires_at = Utc::now() + TimeDelta::try_hours(24).unwrap_or(TimeDelta::zero()); // 24h default

        sqlx::query(
            "INSERT INTO double_opt_in_tokens
               (tenant_id, subscriber_id, consent_type, email,
                token_hash, expires_at, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,NOW())
             ON CONFLICT (tenant_id, subscriber_id, consent_type) DO UPDATE SET
               token_hash = EXCLUDED.token_hash,
               expires_at = EXCLUDED.expires_at",
        )
        .bind(tenant_id)
        .bind(subscriber_id)
        .bind(consent_type.to_string())
        .bind(email)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        info!(%tenant_id, %subscriber_id, %consent_type, "Double opt-in initiated");
        Ok(token)
    }

    /// Confirm double opt-in with token.
    pub async fn confirm_double_opt_in(
        &self,
        tenant_id: &str,
        subscriber_id: &str,
        consent_type: ConsentType,
        token: &str,
    ) -> Result<bool, String> {
        let token_hash = sha256_hex(token);

        let row: Option<(String, String, chrono::DateTime<Utc>)> = sqlx::query_as(
            "SELECT token_hash, email, expires_at FROM double_opt_in_tokens
             WHERE tenant_id = $1 AND subscriber_id = $2 AND consent_type = $3",
        )
        .bind(tenant_id)
        .bind(subscriber_id)
        .bind(consent_type.to_string())
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        let (stored_hash, email, expires_at) = match row {
            Some(r) => r,
            None => return Ok(false),
        };

        if expires_at < Utc::now() {
            // Token expired — clean up
            sqlx::query(
                "DELETE FROM double_opt_in_tokens
                 WHERE tenant_id = $1 AND subscriber_id = $2 AND consent_type = $3",
            )
            .bind(tenant_id)
            .bind(subscriber_id)
            .bind(consent_type.to_string())
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB: {e}"))?;
            return Ok(false);
        }

        if !constant_time_compare(&token_hash, &stored_hash) {
            return Ok(false);
        }

        // Token valid — record consent, delete token
        self.record_consent(
            tenant_id,
            subscriber_id,
            &email,
            consent_type,
            true,
            ConsentSource::DoubleOptIn,
            None,
        )
        .await?;

        sqlx::query(
            "DELETE FROM double_opt_in_tokens
             WHERE tenant_id = $1 AND subscriber_id = $2 AND consent_type = $3",
        )
        .bind(tenant_id)
        .bind(subscriber_id)
        .bind(consent_type.to_string())
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        info!(%tenant_id, %subscriber_id, %consent_type, "Double opt-in confirmed");
        Ok(true)
    }

    /// Get all consent records for a subscriber.
    pub async fn get_consent_records(
        &self,
        tenant_id: &str,
        subscriber_id: &str,
    ) -> Result<Vec<ConsentRecord>, String> {
        let rows: Vec<ConsentRecordRow> = sqlx::query_as(
            "SELECT id, tenant_id, subscriber_id, email, consent_type, granted,
                    granted_at, revoked_at, source, ip_address, user_agent,
                    proof_document, expires_at, metadata
             FROM consent_records
             WHERE tenant_id = $1 AND subscriber_id = $2
             ORDER BY granted_at DESC NULLS LAST",
        )
        .bind(tenant_id)
        .bind(subscriber_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        rows.into_iter().map(|r| r.into_record()).collect()
    }

    /// Get a single consent record by ID.
    pub async fn get_consent_by_id(
        &self,
        consent_id: &str,
    ) -> Result<Option<ConsentRecord>, String> {
        let row: Option<ConsentRecordRow> = sqlx::query_as(
            "SELECT id, tenant_id, subscriber_id, email, consent_type, granted,
                    granted_at, revoked_at, source, ip_address, user_agent,
                    proof_document, expires_at, metadata
             FROM consent_records
             WHERE id = $1",
        )
        .bind(consent_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        match row {
            Some(r) => Ok(Some(r.into_record()?)),
            None => Ok(None),
        }
    }

    /// Generate (or regenerate) a signed consent certificate for an existing consent record.
    /// Returns the certificate JSON string and updates the `proof_document` field in the DB.
    pub async fn generate_consent_certificate(&self, consent_id: &str) -> Result<String, String> {
        let record = self
            .get_consent_by_id(consent_id)
            .await?
            .ok_or_else(|| format!("Consent record not found: {consent_id}"))?;

        let certificate_json = build_consent_certificate(
            &self.config.consent_signing_key,
            &record.id,
            &record.tenant_id,
            &record.subscriber_id,
            &record.email,
            &record.consent_type.to_string(),
            record.granted,
            record.granted_at,
            record.revoked_at,
            &record.source.to_string(),
            record.ip_address.as_deref(),
        )?;

        sqlx::query("UPDATE consent_records SET proof_document = $1 WHERE id = $2")
            .bind(&certificate_json)
            .bind(consent_id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB error updating proof document: {e}"))?;

        Ok(certificate_json)
    }

    // ── Queue Processing ──────────────────────────────────

    /// Enqueue a request for background processing via Redis.
    ///
    /// F: entries carry an enqueue timestamp so a crash between pop and
    /// process never loses a request — stuck entries in the processing list
    /// are requeued by [`GdprAutomation::recover_stuck_processing`].
    async fn enqueue_request(&self, request_id: &str) -> Result<(), String> {
        let mut conn = self.redis.get().await.map_err(|e| format!("Redis: {e}"))?;
        let entry = encode_queue_entry(request_id);
        redis::cmd("RPUSH")
            .arg("gdpr:request_queue")
            .arg(&entry)
            .query_async::<()>(&mut *conn)
            .await
            .map_err(|e| format!("Redis RPUSH: {e}"))?;
        Ok(())
    }

    /// Process next batch of requests from the queue.
    ///
    /// F: items are atomically moved to a processing list (LMOVE, the
    /// RPOPLPUSH pattern) BEFORE processing and only removed after the
    /// outcome is recorded — a crash mid-processing leaves the item
    /// recoverable instead of silently dropped.
    pub async fn process_queue_batch(
        &self,
        max_items: usize,
    ) -> Result<Vec<DataSubjectRequestResult>, String> {
        let mut conn = self.redis.get().await.map_err(|e| format!("Redis: {e}"))?;

        let limit = max_items.min(10); // max 10 per tick
        let mut results = Vec::with_capacity(limit);

        for _ in 0..limit {
            // Atomically pop the oldest entry onto the processing list.
            let item: Option<String> = redis::cmd("LMOVE")
                .arg("gdpr:request_queue")
                .arg("gdpr:request_processing")
                .arg("LEFT")
                .arg("RIGHT")
                .query_async(&mut *conn)
                .await
                .map_err(|e| format!("Redis LMOVE: {e}"))?;

            let entry = match item {
                Some(e) => e,
                None => break,
            };
            let request_id = decode_queue_entry(&entry);

            let outcome = self.process_request(&request_id).await;
            // The item's fate is durably recorded in Postgres (completed /
            // retrying / failed), so it can leave the processing list. On
            // error-without-recording, keep it for the recovery sweep.
            match outcome {
                Ok(r) => {
                    results.push(r);
                    self.ack_processing_entry(&mut conn, &entry).await?;
                }
                Err(e) => {
                    warn!(request_id = %request_id, error = %e, "Failed to process GDPR request — leaving entry for recovery sweep");
                }
            }
        }

        Ok(results)
    }

    /// Remove a processed entry from the processing list.
    async fn ack_processing_entry(
        &self,
        conn: &mut deadpool_redis::Connection,
        entry: &str,
    ) -> Result<(), String> {
        redis::cmd("LREM")
            .arg("gdpr:request_processing")
            .arg(1)
            .arg(entry)
            .query_async::<i64>(&mut *conn)
            .await
            .map_err(|e| format!("Redis LREM: {e}"))?;
        Ok(())
    }

    /// Requeue entries stuck in the processing list longer than
    /// `stale_after_secs` (worker crashed between LMOVE and completion).
    /// Returns the number of requeued entries.
    pub async fn recover_stuck_processing(&self, stale_after_secs: u64) -> Result<usize, String> {
        let mut conn = self.redis.get().await.map_err(|e| format!("Redis: {e}"))?;
        let entries: Vec<String> = redis::cmd("LRANGE")
            .arg("gdpr:request_processing")
            .arg(0)
            .arg(-1)
            .query_async(&mut *conn)
            .await
            .map_err(|e| format!("Redis LRANGE: {e}"))?;

        let cutoff = Utc::now()
            - TimeDelta::try_seconds(stale_after_secs as i64).unwrap_or_else(TimeDelta::zero);
        let mut requeued = 0usize;
        for entry in entries {
            if queue_entry_is_stale(&entry, cutoff) {
                redis::cmd("RPUSH")
                    .arg("gdpr:request_queue")
                    .arg(&entry)
                    .query_async::<()>(&mut *conn)
                    .await
                    .map_err(|e| format!("Redis RPUSH: {e}"))?;
                redis::cmd("LREM")
                    .arg("gdpr:request_processing")
                    .arg(1)
                    .arg(&entry)
                    .query_async::<i64>(&mut *conn)
                    .await
                    .map_err(|e| format!("Redis LREM: {e}"))?;
                requeued += 1;
                warn!(request_id = %decode_queue_entry(&entry), "Recovered stuck GDPR queue entry");
            }
        }
        Ok(requeued)
    }

    // ── Expiry ────────────────────────────────────────────

    /// Expire requests that passed their deadline.
    pub async fn expire_overdue_requests(&self) -> Result<u64, String> {
        let result = sqlx::query(
            "UPDATE data_subject_requests
             SET status = 'expired'
             WHERE status IN ('pending_verification', 'verified')
               AND expires_at < NOW()",
        )
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        let count = result.rows_affected();
        if count > 0 {
            info!(count, "Expired overdue GDPR requests");
        }
        Ok(count)
    }

    /// Expire stale double-opt-in tokens.
    pub async fn expire_stale_opt_in_tokens(&self) -> Result<u64, String> {
        let result = sqlx::query("DELETE FROM double_opt_in_tokens WHERE expires_at < NOW()")
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB: {e}"))?;

        Ok(result.rows_affected())
    }

    /// Data retention:delete old consent records and exports.
    ///
    /// I-3: exports expire after `export_expiration_days` (7 by default),
    /// NOT `data_retention_days`; revoked-consent cleanup also covers rows
    /// with NULL granted_at (never-granted records) older than the cutoff,
    /// keyed on their revocation time.
    pub async fn enforce_retention(&self) -> Result<(u64, u64), String> {
        let (consent_cutoff, export_cutoff) = retention_cutoffs(
            Utc::now(),
            self.config.data_retention_days,
            self.config.export_expiration_days,
        );

        let consents = sqlx::query(
            "DELETE FROM consent_records
             WHERE granted = false
               AND COALESCE(granted_at, revoked_at) < $1",
        )
        .bind(consent_cutoff)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?
        .rows_affected();

        let exports = sqlx::query("DELETE FROM gdpr_exports WHERE created_at < $1")
            .bind(export_cutoff)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB: {e}"))?
            .rows_affected();

        if consents > 0 || exports > 0 {
            info!(consents, exports, "Retention enforcement completed");
        }
        Ok((consents, exports))
    }

    // ── Stats ─────────────────────────────────────────────

    /// Request statistics. `tenant_id: None` aggregates across all tenants
    /// (I-1: the route used to pass a literal "" which always matched zero
    /// rows and reported all-zero stats).
    pub async fn get_request_stats(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let row: Option<(i64, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT
               COUNT(*) FILTER (WHERE status = 'pending_verification'),
               COUNT(*) FILTER (WHERE status = 'verified'),
               COUNT(*) FILTER (WHERE status IN ('processing', 'retrying')),
               COUNT(*) FILTER (WHERE status = 'completed'),
               COUNT(*) FILTER (WHERE status IN ('rejected', 'failed', 'partial'))
             FROM data_subject_requests WHERE ($1::text IS NULL OR tenant_id = $1)",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        let (pending, verified, processing, completed, rejected) = row.unwrap_or_default();

        Ok(serde_json::json!({
            "tenant_id": tenant_id,
            "pending_verification": pending,
            "verified": verified,
            "processing": processing,
            "completed": completed,
            "rejected": rejected,
            "total": pending + verified + processing + completed + rejected,
        }))
    }

    // ── Internal Helpers ──────────────────────────────────

    async fn fetch_request(&self, request_id: &str) -> Result<Option<DataSubjectRequest>, String> {
        let row: Option<RequestRow> = sqlx::query_as(
            "SELECT id, tenant_id, request_type, email, verification_token_hash,
                    verified, verified_at, status, requested_at, processed_at,
                    completed_at, expires_at, result, received_at, identity_verified_at,
                    statutory_due_at, extension_due_at, extension_reason,
                    extension_notified_at
             FROM data_subject_requests WHERE id = $1",
        )
        .bind(request_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB: {e}"))?;

        match row {
            Some(r) => Ok(Some(r.into_request()?)),
            None => Ok(None),
        }
    }

    async fn clear_redis_keys(&self, tenant_id: &str, email: &str) -> Result<(), String> {
        let mut conn = self
            .redis
            .get()
            .await
            .map_err(|e| format!("Redis pool: {e}"))?;
        let keys = [
            format!("subscriber:{}:{}", tenant_id, email),
            format!("engagement:{}:{}", tenant_id, email),
            format!("consent:{}:{}", tenant_id, email),
        ];
        for key in &keys {
            redis::cmd("DEL")
                .arg(key)
                .query_async::<()>(&mut *conn)
                .await
                .map_err(|e| format!("Redis DEL {}: {e}", key))?;
        }
        Ok(())
    }
}

// ─── Utility Functions ──────────────────────────────────────────

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Build a signed consent certificate (proof document).
///
/// Creates a JSON receipt that includes all consent details and an HMAC-SHA256
/// signature over the canonical (sorted-key) JSON representation. The certificate
/// can be independently verified by any party in possession of the signing key.
#[allow(clippy::too_many_arguments)]
fn build_consent_certificate(
    signing_key: &str,
    id: &str,
    tenant_id: &str,
    subscriber_id: &str,
    email: &str,
    consent_type: &str,
    granted: bool,
    granted_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
    source: &str,
    ip_address: Option<&str>,
) -> Result<String, String> {
    let certificate_id = Uuid::new_v4().to_string();
    let generated_at = Utc::now().to_rfc3339();

    // Build canonical data for signing — keys sorted alphabetically
    let mut canonical = serde_json::Map::new();
    canonical.insert("consent_id".into(), serde_json::Value::String(id.into()));
    canonical.insert(
        "consent_type".into(),
        serde_json::Value::String(consent_type.into()),
    );
    canonical.insert("email".into(), serde_json::Value::String(email.into()));
    canonical.insert("granted".into(), serde_json::Value::Bool(granted));
    if let Some(ts) = granted_at {
        canonical.insert(
            "granted_at".into(),
            serde_json::Value::String(ts.to_rfc3339()),
        );
    }
    if let Some(ref ts) = revoked_at {
        canonical.insert(
            "revoked_at".into(),
            serde_json::Value::String(ts.to_rfc3339()),
        );
    }
    if let Some(ip) = ip_address {
        canonical.insert("ip_address".into(), serde_json::Value::String(ip.into()));
    }
    canonical.insert("source".into(), serde_json::Value::String(source.into()));
    canonical.insert(
        "subscriber_id".into(),
        serde_json::Value::String(subscriber_id.into()),
    );
    canonical.insert(
        "tenant_id".into(),
        serde_json::Value::String(tenant_id.into()),
    );

    // Serialize canonical data without whitespace for signing
    let canonical_json =
        serde_json::to_string(&canonical).map_err(|e| format!("JSON serialization: {e}"))?;

    // Compute HMAC-SHA256 signature
    if signing_key.is_empty() {
        return Err(
            "CONSENT_SIGNING_KEY is not configured — cannot generate consent certificates. "
                .to_string(),
        );
    }
    let key = signing_key.as_bytes();

    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
    mac.update(canonical_json.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    // Build the full certificate
    let certificate = serde_json::json!({
        "certificate_id": certificate_id,
        "consent_id": id,
        "tenant_id": tenant_id,
        "subscriber_id": subscriber_id,
        "email": email,
        "consent_type": consent_type,
        "granted": granted,
        "granted_at": granted_at.map(|t| t.to_rfc3339()),
        "revoked_at": revoked_at.map(|t| t.to_rfc3339()),
        "source": source,
        "ip_address": ip_address,
        "signature": signature,
        "signed_fields": [
            "consent_id", "consent_type", "email", "granted", "granted_at",
            "ip_address", "revoked_at", "source", "subscriber_id", "tenant_id"
        ],
        "generated_at": generated_at,
    });

    serde_json::to_string_pretty(&certificate).map_err(|e| format!("JSON serialization: {e}"))
}

/// Remove sensitive internal fields from JSON data.
fn sanitize_pii(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        for key in &[
            "password_hash",
            "internal_notes",
            "api_key_hash",
            "verification_token_hash",
            // F9: the users row is exported anonymized-readable — MFA
            // secrets and recovery hashes are credentials, not readable data.
            "mfa_secret",
            "mfa_recovery_hashes",
        ] {
            obj.remove(*key);
        }
    }
    value
}

// ─── Erasure data map (pure decision logic) ─────────────────────
//
// A: every store is scoped to the data subject (email / subject's user id).
// The old code deleted whole-tenant rows from api_keys, sessions,
// contact_list_members, webhooks and invoices — one subject's Art. 17
// request destroyed unrelated users' data and statutory billing records.

/// One store touched during an Art. 17 erasure.
#[derive(Debug, Clone, PartialEq)]
pub enum ErasureStore {
    /// DELETE rows where `{email_column} = subject email AND tenant_id = tenant`.
    TableBySubjectEmail {
        name: &'static str,
        table: &'static str,
        email_column: &'static str,
    },
    /// DELETE sessions belonging to the users row matching the subject email.
    SessionsByUserEmail,
    /// A-3: retained (statutory) store whose email-bearing columns are
    /// anonymized with a redaction marker instead of being deleted. Each
    /// candidate column absent from the deployment is tolerated.
    AnonymizeSubjectEmail {
        name: &'static str,
        table: &'static str,
        columns: &'static [&'static str],
    },
    /// F82: invoices — statutory records whose SUBJECT PII lives in the
    /// immutable `billing_address` snapshot JSON. The snapshot's email is
    /// rewritten with the redaction marker (row preserved); the financial
    /// record itself is retained. Schema errors here FAIL the erasure:
    /// invoices are a required canonical store, not an optional one.
    AnonymizeInvoiceSnapshot { name: &'static str },
    /// F1: canonical message content (migration 073). The subject's copy is
    /// anonymized — recipients arrays, subject line and bodies are redacted
    /// while the row (a statutory sending record) survives. Deleting the row
    /// would destroy other recipients' records of the same send.
    AnonymizeMessageContent,
    /// AI assistant chat audit rows for the subject's user account
    /// (migration 123). Conversations are not statutory records — deleted.
    AiChatByUserEmail,
    /// F1/F9: the subject's platform account. Art. 17 hygiene keeps a
    /// tombstone row (id + tenant linkage + `erased` status) with every
    /// PII field redacted, so audit/history references don't dangle.
    AnonymizeUserTombstone,
    /// F1: ClickHouse analytics events. Config-gated best-effort
    /// `ALTER TABLE events DELETE WHERE recipient = ...` — reported honestly
    /// on the certificate whether configured, submitted or failed.
    ClickHouseEvents,
    /// Store intentionally retained (with reason) — never deleted.
    Retained {
        name: &'static str,
        reason: &'static str,
    },
}

impl ErasureStore {
    fn name(&self) -> &'static str {
        match self {
            Self::TableBySubjectEmail { name, .. } => name,
            Self::SessionsByUserEmail => "sessions",
            Self::AiChatByUserEmail => "ai_chat_messages",
            Self::AnonymizeSubjectEmail { name, .. } => name,
            Self::AnonymizeInvoiceSnapshot { name } => name,
            Self::AnonymizeMessageContent => "messages",
            Self::AnonymizeUserTombstone => "users",
            Self::ClickHouseEvents => "clickhouse_events",
            Self::Retained { name, .. } => name,
        }
    }
}

/// The complete erasure data map, mirroring the access-export data map.
///
/// F1: every store here is REAL — it exists in the canonical migration chain
/// (`contacts` 068/075, `events` 075, `messages` 073, `users` 052/064,
/// `sessions` 069, plus the 038 compliance tables). The previous map deleted
/// from `subscribers`/`message_events`/`tracking_events`/
/// `engagement_events`/`subscriber_analytics`, which exist only in test
/// fixtures — production erasures reported "deleted" while touching nothing
/// and the real PII stores kept every row.
pub fn erasure_stores() -> Vec<ErasureStore> {
    use ErasureStore::*;
    vec![
        // Canonical subscriber/contact records.
        TableBySubjectEmail {
            name: "contacts",
            table: "contacts",
            email_column: "email",
        },
        // Kept for deployments that provision the CP list store; on the
        // canonical chain it is absent and honestly reported as skipped.
        TableBySubjectEmail {
            name: "contact_list_members",
            table: "contact_list_members",
            email_column: "subscriber_email",
        },
        // Canonical event store (075) — recipient match.
        TableBySubjectEmail {
            name: "events",
            table: "events",
            email_column: "recipient",
        },
        // Canonical message content (073) — anonymize, never delete.
        AnonymizeMessageContent,
        SessionsByUserEmail,
        // AI assistant conversations (migration 123) — user-scoped chat
        // history; no statutory retention, deleted with the account.
        AiChatByUserEmail,
        // The subject's account, anonymized to a tombstone. AFTER sessions:
        // the session purge resolves the users row by email, and the
        // tombstone rewrites that email.
        AnonymizeUserTombstone,
        TableBySubjectEmail {
            name: "consent_records",
            table: "consent_records",
            email_column: "email",
        },
        TableBySubjectEmail {
            name: "double_opt_in_tokens",
            table: "double_opt_in_tokens",
            email_column: "email",
        },
        TableBySubjectEmail {
            name: "gdpr_exports",
            table: "gdpr_exports",
            email_column: "email",
        },
        // F1: ClickHouse analytics is a real PII store — best-effort purge.
        ClickHouseEvents,
        // Accountability trail: subject-referencing audit entries are
        // records of processing (Art. 30) and are retained; they appear in
        // BOTH maps (the SAR exports them, erasure retains them — F9).
        Retained {
            name: "audit_logs",
            reason: "retained: accountability trail (Art. 30 records of processing)",
        },
        // A-5: suppression must SURVIVE erasure — deleting it would enable
        // re-mailing a complained address (CAN-SPAM / GDPR opt-out violation).
        // Retention is a legitimate interest (Art. 17(3)(e) / Recital 65).
        Retained {
            name: "suppression_list",
            reason: "retained: opt-out enforcement (CAN-SPAM/GDPR legitimate interest)",
        },
        // A-3: billing records have statutory retention — anonymize, never
        // delete. F82: the subject's PII on an invoice lives in the
        // immutable billing_address SNAPSHOT (there is no customer_email
        // column; querying one failed with 42703). The snapshot's email is
        // redacted in place; the financial record survives.
        AnonymizeInvoiceSnapshot { name: "invoices" },
        // A-4: tenant-owned resources with no per-subject ownership column —
        // deleting them would destroy unrelated users' data.
        Retained {
            name: "api_keys",
            reason: "retained: tenant-owned resource (no subject ownership column)",
        },
        Retained {
            name: "webhooks",
            reason: "retained: tenant-owned resource (no subject ownership column)",
        },
    ]
}

/// Per-store erasure outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreErasureStatus {
    Deleted,
    Anonymized,
    Retained(&'static str),
    /// Table/column absent in this deployment — reported, never silently
    /// counted as deleted.
    SkippedMissingTable,
    /// F1: the store is a real PII store but this deployment has no purge
    /// path configured (e.g. ClickHouse erasure disabled) — reported on the
    /// certificate, never counted as deleted.
    SkippedNotConfigured,
    /// F1: best-effort store (ClickHouse mutation) failed. The Postgres
    /// erasure continues; the certificate records the gap and the request is
    /// `partial`, not `failed`.
    BestEffortFailed,
    /// F1: the best-effort mutation was SUBMITTED (ClickHouse applies
    /// `ALTER ... DELETE` asynchronously — submission is the strongest
    /// synchronous guarantee available).
    MutationSubmitted,
    Failed,
}

#[derive(Debug, Clone)]
pub struct StoreErasureResult {
    pub store: &'static str,
    pub status: StoreErasureStatus,
    pub rows_affected: u64,
    pub error: Option<String>,
}

/// Overall erasure outcome derived from per-store results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasureOverall {
    Completed,
    Partial,
    Failed,
}

pub fn summarize_erasure(results: &[StoreErasureResult]) -> ErasureOverall {
    if results
        .iter()
        .any(|r| matches!(r.status, StoreErasureStatus::Failed))
    {
        ErasureOverall::Failed
    } else if results.iter().any(|r| {
        matches!(
            r.status,
            StoreErasureStatus::SkippedMissingTable
                | StoreErasureStatus::SkippedNotConfigured
                | StoreErasureStatus::BestEffortFailed
        )
    }) {
        ErasureOverall::Partial
    } else {
        ErasureOverall::Completed
    }
}

/// B: build the deletion confirmation from the ACTUAL per-store outcomes.
/// The blanket "All personal data has been permanently erased" claim is only
/// used when every applicable store really was deleted/anonymized.
pub fn build_deletion_confirmation(
    request_id: &str,
    tenant_id: &str,
    email: &str,
    results: &[StoreErasureResult],
) -> serde_json::Value {
    let overall = summarize_erasure(results);
    let stores: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "store": r.store,
                "status": match &r.status {
                    StoreErasureStatus::Deleted => "deleted",
                    StoreErasureStatus::Anonymized => "anonymized",
                    StoreErasureStatus::Retained(_) => "retained",
                    StoreErasureStatus::SkippedMissingTable => "skipped_missing_table",
                    StoreErasureStatus::SkippedNotConfigured => "skipped_not_configured",
                    StoreErasureStatus::BestEffortFailed => "best_effort_failed",
                    StoreErasureStatus::MutationSubmitted => "mutation_submitted",
                    StoreErasureStatus::Failed => "failed",
                },
                "rows_affected": r.rows_affected,
                "detail": match &r.status {
                    StoreErasureStatus::Retained(reason) => serde_json::json!(reason),
                    _ => serde_json::Value::Null,
                },
            })
        })
        .collect();
    let deleted: u64 = results.iter().map(|r| r.rows_affected).sum();

    let confirmation_text = match overall {
        ErasureOverall::Completed => {
            "All in-scope personal data has been erased or anonymized as detailed per store, per GDPR Article 17."
        }
        ErasureOverall::Partial => {
            "Erasure partially completed: some data stores were absent, not configured, or best-effort failed in this deployment and are listed per store. This certificate does NOT claim full erasure."
        }
        ErasureOverall::Failed => {
            "Erasure failed for one or more data stores; no erasure is certified."
        }
    };

    serde_json::json!({
        "certificate_id": Uuid::new_v4().to_string(),
        "request_id": request_id,
        "tenant_id": tenant_id,
        "email": email,
        "deleted_at": Utc::now().to_rfc3339(),
        "records_deleted": deleted,
        "overall": match overall {
            ErasureOverall::Completed => "completed",
            ErasureOverall::Partial => "partial",
            ErasureOverall::Failed => "failed",
        },
        "stores": stores,
        "confirmation": confirmation_text,
    })
}

/// Postgres undefined_table (42P01).
fn is_missing_table(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c == "42P01")
        .unwrap_or(false)
}

/// Postgres undefined_table (42P01) or undefined_column (42703) — the store
/// (table or its expected subject-scoping column) is not present in this
/// deployment.
fn is_missing_store(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c == "42P01" || c == "42703")
        .unwrap_or(false)
}

/// Stable redaction marker replacing a subject's email in retained records.
pub fn redact_marker(email: &str) -> String {
    format!("erased+{}@invalid", &sha256_hex(email)[..16])
}

/// F9: tombstone email for the subject's `users` row. Embeds the tenant so
/// the globally-UNIQUE users.email never collides when the same subject is
/// erased in two tenants.
pub fn user_tombstone_marker(email: &str, tenant_id: &str) -> String {
    let tenant: String = tenant_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!(
        "erased+{}-{}@invalid",
        &sha256_hex(email)[..12],
        &tenant[..tenant.len().min(13)]
    )
}

/// Textually replace occurrences of the subject email in a JSON value with
/// the redaction marker (anonymized view of retained records). Matching is
/// ASCII-case-insensitive: writers are inconsistent about email case, and an
/// exact-case replace would leave the mixed-case copy of the address in the
/// "anonymized" export (F9).
pub fn anonymize_json_text(
    value: serde_json::Value,
    email: &str,
    marker: &str,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            serde_json::Value::String(replace_ignore_ascii_case(&s, email, marker))
        }
        serde_json::Value::Array(a) => serde_json::Value::Array(
            a.into_iter()
                .map(|v| anonymize_json_text(v, email, marker))
                .collect(),
        ),
        serde_json::Value::Object(o) => serde_json::Value::Object(
            o.into_iter()
                .map(|(k, v)| (k, anonymize_json_text(v, email, marker)))
                .collect(),
        ),
        other => other,
    }
}

/// Replace every ASCII-case-insensitive occurrence of `needle` in `haystack`.
fn replace_ignore_ascii_case(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return haystack.to_string();
    }
    let hay = haystack.as_bytes();
    let ned = needle.as_bytes();
    let mut out = String::with_capacity(haystack.len());
    let mut i = 0;
    while i < hay.len() {
        if i + ned.len() <= hay.len()
            && hay[i..i + ned.len()]
                .iter()
                .zip(ned)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            out.push_str(replacement);
            i += ned.len();
        } else {
            // Copy one full UTF-8 code point (never split a multi-byte char).
            let step = utf8_char_width(hay[i]).max(1) as usize;
            let end = (i + step).min(hay.len());
            out.push_str(&haystack[i..end]);
            i = end;
        }
    }
    out
}

/// Width in bytes of the UTF-8 code point starting with `first_byte`.
fn utf8_char_width(first_byte: u8) -> u8 {
    match first_byte {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

// ─── Retry decision (pure) ──────────────────────────────────────

/// Maximum processing attempts before a request is marked `failed`.
pub const MAX_RETRY_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryStatus {
    Retrying,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryDecision {
    pub attempt: u32,
    pub status: RetryStatus,
}

/// F: decide the next state after a processing failure. Attempts 1..3 retry;
/// the 3rd failure marks the request `failed`.
pub fn next_retry_decision(attempt: u32) -> RetryDecision {
    if attempt >= MAX_RETRY_ATTEMPTS {
        RetryDecision {
            attempt,
            status: RetryStatus::Failed,
        }
    } else {
        RetryDecision {
            attempt,
            status: RetryStatus::Retrying,
        }
    }
}

// ─── Access-export manifest (pure) ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportStoreStatus {
    Included(usize),
    SkippedMissing,
    /// F9: in the DSR data map but carrying no personal data of the subject
    /// (tenant-owned resources) — listed in the manifest for transparency.
    NotSubjectData,
    /// F9: a real analytics store (ClickHouse) this export cannot query —
    /// declared in the manifest instead of silently omitted. The erasure
    /// side submits a best-effort mutation against it.
    NotExportable,
}

#[derive(Debug, Clone)]
pub struct StoreExportResult {
    pub store: &'static str,
    pub status: ExportStoreStatus,
}

impl StoreExportResult {
    pub fn included(store: &'static str, count: usize) -> Self {
        Self {
            store,
            status: ExportStoreStatus::Included(count),
        }
    }

    pub fn skipped(store: &'static str, err: &sqlx::Error) -> Self {
        let _ = err;
        Self {
            store,
            status: ExportStoreStatus::SkippedMissing,
        }
    }

    pub fn not_subject_data(store: &'static str) -> Self {
        Self {
            store,
            status: ExportStoreStatus::NotSubjectData,
        }
    }

    pub fn not_exportable(store: &'static str) -> Self {
        Self {
            store,
            status: ExportStoreStatus::NotExportable,
        }
    }
}

/// F9: the store names the SAR export reads — exactly the erasure map's
/// names. Both directions of a DSR must cover the same stores: data the
/// platform erases on request is data it must also disclose on request.
pub fn export_store_names() -> Vec<&'static str> {
    erasure_stores().iter().map(|s| s.name()).collect()
}

/// G: explicit export manifest — per-store inventory plus a truncation flag
/// so a capped message history is never presented as complete.
pub fn build_export_manifest(stores: &[StoreExportResult], truncated: bool) -> serde_json::Value {
    let store_map: serde_json::Map<String, serde_json::Value> = stores
        .iter()
        .map(|s| {
            let v = match &s.status {
                ExportStoreStatus::Included(n) => serde_json::json!({
                    "included": true,
                    "records": n,
                }),
                ExportStoreStatus::SkippedMissing => serde_json::json!({
                    "included": false,
                    "reason": "store not present in this deployment",
                }),
                ExportStoreStatus::NotSubjectData => serde_json::json!({
                    "included": false,
                    "reason": "tenant-owned resource: no personal data of the subject",
                }),
                ExportStoreStatus::NotExportable => serde_json::json!({
                    "included": false,
                    "reason": "analytics store (ClickHouse): not queried by this export; the erasure flow submits a best-effort mutation against it",
                }),
            };
            (s.store.to_string(), v)
        })
        .collect();

    serde_json::json!({
        "generated_at": Utc::now().to_rfc3339(),
        "stores": serde_json::Value::Object(store_map),
        "truncated": truncated,
        "truncation_note": if truncated {
            "message_history capped at access_request_max_messages; more records exist"
        } else {
            "no store was truncated"
        },
    })
}

// ─── Queue entry codec (pure) ───────────────────────────────────

/// F: queue entries are timestamped JSON so the recovery sweep can detect
/// crashed workers. Plain-string entries (legacy format) still decode.
pub fn encode_queue_entry(request_id: &str) -> String {
    serde_json::json!({
        "id": request_id,
        "at": Utc::now().to_rfc3339(),
    })
    .to_string()
}

pub fn decode_queue_entry(entry: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(entry) {
        if let Some(id) = v.get("id").and_then(|i| i.as_str()) {
            return id.to_string();
        }
    }
    entry.to_string()
}

/// An entry is stale when it is older than the cutoff, or when it carries no
/// timestamp at all (legacy entry — assume abandoned).
pub fn queue_entry_is_stale(entry: &str, cutoff: chrono::DateTime<Utc>) -> bool {
    match serde_json::from_str::<serde_json::Value>(entry) {
        Ok(v) => match v.get("at").and_then(|a| a.as_str()) {
            Some(at) => chrono::DateTime::parse_from_rfc3339(at)
                .map(|t| t.with_timezone(&Utc) < cutoff)
                .unwrap_or(true),
            None => true,
        },
        Err(_) => true,
    }
}

// ─── Retention cutoffs (pure) ───────────────────────────────────

/// I-3: consents are purged after `data_retention_days`, but exports after
/// the much shorter `export_expiration_days` (7 days by default).
pub fn retention_cutoffs(
    now: chrono::DateTime<Utc>,
    data_retention_days: i64,
    export_expiration_days: i64,
) -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    (
        now - Duration::days(data_retention_days),
        now - Duration::days(export_expiration_days),
    )
}

// ─── DB Row Helpers ─────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct RequestRow {
    id: String,
    tenant_id: String,
    request_type: String,
    email: String,
    verification_token_hash: String,
    verified: bool,
    verified_at: Option<chrono::DateTime<Utc>>,
    status: String,
    requested_at: chrono::DateTime<Utc>,
    processed_at: Option<chrono::DateTime<Utc>>,
    completed_at: Option<chrono::DateTime<Utc>>,
    expires_at: chrono::DateTime<Utc>,
    result: Option<serde_json::Value>,
    received_at: Option<chrono::DateTime<Utc>>,
    identity_verified_at: Option<chrono::DateTime<Utc>>,
    statutory_due_at: Option<chrono::DateTime<Utc>>,
    extension_due_at: Option<chrono::DateTime<Utc>>,
    extension_reason: Option<String>,
    extension_notified_at: Option<chrono::DateTime<Utc>>,
}

impl RequestRow {
    fn into_request(self) -> Result<DataSubjectRequest, String> {
        let request_type = match self.request_type.as_str() {
            "access" => DataSubjectRequestType::Access,
            "erasure" => DataSubjectRequestType::Erasure,
            "portability" => DataSubjectRequestType::Portability,
            "rectification" => DataSubjectRequestType::Rectification,
            "restriction" => DataSubjectRequestType::Restriction,
            "objection" => DataSubjectRequestType::Objection,
            other => return Err(format!("Unknown request type: {other}")),
        };

        let status = match self.status.as_str() {
            "pending_verification" => RequestStatus::PendingVerification,
            "verified" => RequestStatus::Verified,
            "processing" => RequestStatus::Processing,
            "completed" => RequestStatus::Completed,
            "rejected" => RequestStatus::Rejected,
            "expired" => RequestStatus::Expired,
            "pending_manual_review" => RequestStatus::PendingManualReview,
            "retrying" => RequestStatus::Retrying,
            "failed" => RequestStatus::Failed,
            "partial" => RequestStatus::Partial,
            other => return Err(format!("Unknown status: {other}")),
        };

        Ok(DataSubjectRequest {
            id: self.id,
            tenant_id: self.tenant_id,
            request_type,
            email: self.email,
            verification_token_hash: self.verification_token_hash,
            verified: self.verified,
            verified_at: self.verified_at,
            status,
            requested_at: self.requested_at,
            processed_at: self.processed_at,
            completed_at: self.completed_at,
            expires_at: self.expires_at,
            result: self.result,
            received_at: self.received_at,
            identity_verified_at: self.identity_verified_at,
            statutory_due_at: self.statutory_due_at,
            extension_due_at: self.extension_due_at,
            extension_reason: self.extension_reason,
            extension_notified_at: self.extension_notified_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ConsentRecordRow {
    id: String,
    tenant_id: String,
    subscriber_id: String,
    email: String,
    consent_type: String,
    granted: bool,
    granted_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
    source: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    proof_document: Option<String>,
    expires_at: Option<chrono::DateTime<Utc>>,
    metadata: serde_json::Value,
}

impl ConsentRecordRow {
    fn into_record(self) -> Result<ConsentRecord, String> {
        let consent_type = match self.consent_type.as_str() {
            "marketing" => ConsentType::Marketing,
            "transactional" => ConsentType::Transactional,
            "analytics" => ConsentType::Analytics,
            "profiling" => ConsentType::Profiling,
            "third_party" => ConsentType::ThirdParty,
            "data_processing" => ConsentType::DataProcessing,
            other => return Err(format!("Unknown consent type: {other}")),
        };

        let source = match self.source.as_str() {
            "form" | "web_form" => ConsentSource::Form,
            "api" => ConsentSource::Api,
            "import" => ConsentSource::Import,
            "double_opt_in" => ConsentSource::DoubleOptIn,
            "preference_center" => ConsentSource::PreferenceCenter,
            "system" => ConsentSource::System,
            other => return Err(format!("Unknown source: {other}")),
        };

        Ok(ConsentRecord {
            id: self.id,
            tenant_id: self.tenant_id,
            subscriber_id: self.subscriber_id,
            email: self.email,
            consent_type,
            granted: self.granted,
            granted_at: self.granted_at,
            revoked_at: self.revoked_at,
            source,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            proof_document: self.proof_document,
            expires_at: self.expires_at,
            metadata: self.metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex_deterministic() {
        let h1 = sha256_hex("hello");
        let h2 = sha256_hex("hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 256 bits = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_sha256_hex_different_inputs() {
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
    }

    #[test]
    fn test_constant_time_compare_equal() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(constant_time_compare("", ""));
    }

    #[test]
    fn test_constant_time_compare_different() {
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("abc", "abcd"));
    }

    #[test]
    fn test_sanitize_pii_removes_sensitive_fields() {
        let data = serde_json::json!({
            "email": "user@example.com",
            "name": "Test User",
            "password_hash": "secret",
            "api_key_hash": "also_secret",
            "verification_token_hash": "another_secret",
            "internal_notes": "private",
        });
        let sanitized = sanitize_pii(data);
        let obj = sanitized.as_object().unwrap();
        assert!(obj.contains_key("email"));
        assert!(obj.contains_key("name"));
        assert!(!obj.contains_key("password_hash"));
        assert!(!obj.contains_key("api_key_hash"));
        assert!(!obj.contains_key("verification_token_hash"));
        assert!(!obj.contains_key("internal_notes"));
    }

    #[test]
    fn test_sanitize_pii_preserves_non_object() {
        let data = serde_json::json!("just a string");
        let sanitized = sanitize_pii(data.clone());
        assert_eq!(sanitized, data);
    }

    #[test]
    fn test_request_row_parsing() {
        let now = Utc::now();
        let row = RequestRow {
            id: "r1".into(),
            tenant_id: "t1".into(),
            request_type: "erasure".into(),
            email: "user@example.com".into(),
            verification_token_hash: "abc123".into(),
            verified: true,
            verified_at: Some(now),
            status: "verified".into(),
            requested_at: now,
            processed_at: None,
            completed_at: None,
            expires_at: now,
            result: None,
            received_at: Some(now),
            identity_verified_at: None,
            statutory_due_at: Some(now),
            extension_due_at: None,
            extension_reason: None,
            extension_notified_at: None,
        };
        let req = row.into_request().unwrap();
        assert_eq!(req.request_type, DataSubjectRequestType::Erasure);
        assert_eq!(req.status, RequestStatus::Verified);
        assert!(req.verified);
    }

    #[test]
    fn test_request_row_invalid_type() {
        let now = Utc::now();
        let row = RequestRow {
            id: "r1".into(),
            tenant_id: "t1".into(),
            request_type: "invalid_type".into(),
            email: "".into(),
            verification_token_hash: "".into(),
            verified: false,
            verified_at: None,
            status: "verified".into(),
            requested_at: now,
            processed_at: None,
            completed_at: None,
            expires_at: now,
            result: None,
            received_at: Some(now),
            identity_verified_at: None,
            statutory_due_at: Some(now),
            extension_due_at: None,
            extension_reason: None,
            extension_notified_at: None,
        };
        assert!(row.into_request().is_err());
    }

    #[test]
    fn test_consent_record_row_parsing() {
        let now = Utc::now();
        let row = ConsentRecordRow {
            id: "c1".into(),
            tenant_id: "t1".into(),
            subscriber_id: "s1".into(),
            email: "u@example.com".into(),
            consent_type: "marketing".into(),
            granted: true,
            granted_at: Some(now),
            revoked_at: None,
            source: "web_form".into(),
            ip_address: Some("192.168.1.1".into()),
            user_agent: None,
            proof_document: None,
            expires_at: None,
            metadata: serde_json::json!({}),
        };
        let record = row.into_record().unwrap();
        assert_eq!(record.consent_type, ConsentType::Marketing);
        assert!(record.granted);
        assert_eq!(record.source, ConsentSource::Form);
    }

    #[test]
    fn test_consent_record_row_revoked() {
        let now = Utc::now();
        let row = ConsentRecordRow {
            id: "c2".into(),
            tenant_id: "t1".into(),
            subscriber_id: "s1".into(),
            email: "u@example.com".into(),
            consent_type: "analytics".into(),
            granted: false,
            granted_at: None,
            revoked_at: Some(now),
            source: "system".into(),
            ip_address: None,
            user_agent: None,
            proof_document: None,
            expires_at: None,
            metadata: serde_json::json!({}),
        };
        let record = row.into_record().unwrap();
        assert!(!record.granted);
        assert_eq!(record.consent_type, ConsentType::Analytics);
    }

    #[test]
    fn test_all_request_types_parse() {
        let now = Utc::now();
        let types = [
            "access",
            "erasure",
            "portability",
            "rectification",
            "restriction",
            "objection",
        ];
        for t in types {
            let row = RequestRow {
                id: "r".into(),
                tenant_id: "t".into(),
                request_type: t.into(),
                email: "e@e.com".into(),
                verification_token_hash: "h".into(),
                verified: false,
                verified_at: None,
                status: "completed".into(),
                requested_at: now,
                processed_at: None,
                completed_at: None,
                expires_at: now,
                result: None,
                received_at: Some(now),
                identity_verified_at: None,
                statutory_due_at: Some(now),
                extension_due_at: None,
                extension_reason: None,
                extension_notified_at: None,
            };
            assert!(
                row.into_request().is_ok(),
                "Failed to parse request type: {}",
                t
            );
        }
    }

    #[test]
    fn test_all_consent_types_parse() {
        let _now = Utc::now();
        let types = [
            "marketing",
            "transactional",
            "analytics",
            "profiling",
            "third_party",
            "data_processing",
        ];
        for t in types {
            let row = ConsentRecordRow {
                id: "c".into(),
                tenant_id: "t".into(),
                subscriber_id: "s".into(),
                email: "e@e.com".into(),
                consent_type: t.into(),
                granted: true,
                granted_at: None,
                revoked_at: None,
                source: "api".into(),
                ip_address: None,
                user_agent: None,
                proof_document: None,
                expires_at: None,
                metadata: serde_json::json!({}),
            };
            assert!(
                row.into_record().is_ok(),
                "Failed to parse consent type: {}",
                t
            );
        }
    }

    #[test]
    fn test_all_statuses_parse() {
        let now = Utc::now();
        let statuses = [
            "pending_verification",
            "verified",
            "processing",
            "completed",
            "rejected",
            "expired",
            "pending_manual_review",
            "retrying",
            "failed",
            "partial",
        ];
        for s in statuses {
            let row = RequestRow {
                id: "r".into(),
                tenant_id: "t".into(),
                request_type: "access".into(),
                email: "e@e.com".into(),
                verification_token_hash: "h".into(),
                verified: false,
                verified_at: None,
                status: s.into(),
                requested_at: now,
                processed_at: None,
                completed_at: None,
                expires_at: now,
                result: None,
                received_at: Some(now),
                identity_verified_at: None,
                statutory_due_at: Some(now),
                extension_due_at: None,
                extension_reason: None,
                extension_notified_at: None,
            };
            assert!(row.into_request().is_ok(), "Failed to parse status: {}", s);
        }
    }
    // ── A/F1: erasure plan is subject-scoped and canonical ────

    /// Every SQL-bearing store must key on the subject's email (or the
    /// subject's user id) — no whole-tenant deletes — and every store must
    /// exist in the canonical migration chain (audit F1: the old map deleted
    /// from fixture-only tables while the real PII stores kept every row).
    #[test]
    fn test_erasure_plan_is_subject_scoped_and_canonical() {
        let stores = erasure_stores();
        assert!(stores.len() >= 14, "expected the full data map");

        for store in &stores {
            match store {
                ErasureStore::TableBySubjectEmail {
                    name,
                    table,
                    email_column,
                } => {
                    assert!(!table.is_empty());
                    assert!(
                        email_column.contains("email") || *email_column == "recipient",
                        "{name} must scope deletes to an email-bearing column"
                    );
                }
                ErasureStore::SessionsByUserEmail => { /* scoped via users.email lookup */ }
                ErasureStore::AiChatByUserEmail => { /* scoped via users.email lookup */ }
                ErasureStore::AnonymizeSubjectEmail { name, columns, .. } => {
                    assert!(
                        !columns.is_empty(),
                        "{name} anonymization needs candidate columns"
                    );
                }
                ErasureStore::AnonymizeInvoiceSnapshot { .. } => {
                    /* scoped via the billing-address snapshot email (F82) */
                }
                ErasureStore::AnonymizeMessageContent => { /* canonical messages store */ }
                ErasureStore::AnonymizeUserTombstone => { /* canonical users store */ }
                ErasureStore::ClickHouseEvents => { /* best-effort analytics purge */ }
                ErasureStore::Retained { name, reason } => {
                    assert!(!reason.is_empty(), "{name} retention needs a reason");
                }
            }
        }

        let names: Vec<&str> = stores
            .iter()
            .map(|s| match s {
                ErasureStore::TableBySubjectEmail { name, .. } => *name,
                ErasureStore::SessionsByUserEmail => "sessions",
                ErasureStore::AiChatByUserEmail => "ai_chat_messages",
                ErasureStore::AnonymizeSubjectEmail { name, .. } => *name,
                ErasureStore::AnonymizeInvoiceSnapshot { name } => *name,
                ErasureStore::AnonymizeMessageContent => "messages",
                ErasureStore::AnonymizeUserTombstone => "users",
                ErasureStore::ClickHouseEvents => "clickhouse_events",
                ErasureStore::Retained { name, .. } => *name,
            })
            .collect();

        // F1: the phantom tables (test fixtures only) must be GONE from the
        // erasure map — deleting from them attested erasure that never
        // happened.
        for phantom in [
            "subscribers",
            "message_events",
            "tracking_events",
            "engagement_events",
            "subscriber_analytics",
        ] {
            assert!(
                !names.contains(&phantom),
                "{phantom} exists only in test fixtures — it must not be in the erasure map"
            );
        }

        // The real canonical PII stores are all covered.
        for canonical in [
            "contacts",
            "events",
            "messages",
            "users",
            "sessions",
            "consent_records",
            "double_opt_in_tokens",
            "gdpr_exports",
            "clickhouse_events",
            "invoices",
        ] {
            assert!(
                names.contains(&canonical),
                "{canonical} is a real store and must be in the erasure map"
            );
        }

        // Invoices are anonymized through the billing-address snapshot
        // (A-3, F82), never deleted.
        assert!(stores.iter().any(|s| matches!(
            s,
            ErasureStore::AnonymizeInvoiceSnapshot { name } if *name == "invoices"
        )));

        for tenant_resource in ["api_keys", "webhooks", "suppression_list"] {
            let entry = stores
                .iter()
                .find(|s| matches!(s, ErasureStore::Retained { name, .. } if *name == tenant_resource))
                .unwrap_or_else(|| panic!("{tenant_resource} must be in the erasure plan"));
            assert!(
                matches!(entry, ErasureStore::Retained { .. }),
                "{tenant_resource} must be retained, not deleted"
            );
        }
        assert!(names.contains(&"sessions"), "sessions must be in the plan");
    }

    // ── F9: SAR/erasure symmetry ───────────────────────────────

    /// The access export and the Art.17 erasure must cover the SAME store
    /// set — data the platform erases on request is data it must disclose
    /// on request. This pins the exact list `process_access_request`
    /// collects; adding a store to one side without the other fails here.
    #[test]
    fn test_sar_export_and_erasure_maps_are_symmetric() {
        let export_reads = [
            "contacts",
            "events",
            "messages",
            "users",
            "consent_records",
            "double_opt_in_tokens",
            "gdpr_exports",
            "sessions",
            "ai_chat_messages",
            "suppression_list",
            "contact_list_members",
            "invoices",
            "audit_logs",
            // NotSubjectData / NotExportable entries — in the map,
            // transparently labelled.
            "api_keys",
            "webhooks",
            "clickhouse_events",
        ];
        let mut from_erasure: Vec<&str> = export_store_names().to_vec();
        let mut from_export = export_reads.to_vec();
        from_erasure.sort_unstable();
        from_export.sort_unstable();
        assert_eq!(
            from_erasure, from_export,
            "SAR export and erasure data maps must mirror each other (F9)"
        );
    }

    // ── B: honest summarization + certificate ───────────────────

    fn store_result(store: &'static str, status: StoreErasureStatus) -> StoreErasureResult {
        StoreErasureResult {
            store,
            status,
            rows_affected: 0,
            error: None,
        }
    }

    #[test]
    fn test_summarize_erasure_completed() {
        let results = vec![
            store_result("subscribers", StoreErasureStatus::Deleted),
            store_result("invoices", StoreErasureStatus::Retained("statutory")),
        ];
        assert_eq!(summarize_erasure(&results), ErasureOverall::Completed);
    }

    #[test]
    fn test_summarize_erasure_partial_on_missing_table() {
        let results = vec![
            store_result("subscribers", StoreErasureStatus::Deleted),
            store_result("tracking_events", StoreErasureStatus::SkippedMissingTable),
        ];
        assert_eq!(summarize_erasure(&results), ErasureOverall::Partial);
    }

    #[test]
    fn test_summarize_erasure_failed() {
        let results = vec![
            store_result("subscribers", StoreErasureStatus::Deleted),
            store_result("consent_records", StoreErasureStatus::Failed),
        ];
        assert_eq!(summarize_erasure(&results), ErasureOverall::Failed);
    }

    /// B: the certificate must never claim full erasure when a store failed.
    #[test]
    fn test_certificate_failed_store_does_not_claim_erasure() {
        let mut results = vec![
            store_result("subscribers", StoreErasureStatus::Deleted),
            store_result("message_events", StoreErasureStatus::Deleted),
        ];
        results.push(StoreErasureResult {
            store: "consent_records",
            status: StoreErasureStatus::Failed,
            rows_affected: 0,
            error: Some("db down".into()),
        });
        let cert = build_deletion_confirmation("req-1", "t1", "u@x.com", &results);
        assert_eq!(cert["overall"], "failed");
        let text = cert["confirmation"].as_str().unwrap();
        assert!(!text
            .to_lowercase()
            .contains("all personal data has been permanently erased"));
        assert!(text.contains("no erasure is certified"));
    }

    /// B: partial (missing store) certificates list the skipped stores.
    #[test]
    fn test_certificate_partial_lists_skipped_stores() {
        let results = vec![
            store_result("subscribers", StoreErasureStatus::Deleted),
            store_result("tracking_events", StoreErasureStatus::SkippedMissingTable),
        ];
        let cert = build_deletion_confirmation("req-1", "t1", "u@x.com", &results);
        assert_eq!(cert["overall"], "partial");
        let stores = cert["stores"].as_array().unwrap();
        assert_eq!(stores.len(), 2);
        assert_eq!(stores[1]["store"], "tracking_events");
        assert_eq!(stores[1]["status"], "skipped_missing_table");
    }

    /// B: only a fully-applied plan earns the "all in-scope" wording.
    #[test]
    fn test_certificate_completed_claims_scoped_erasure() {
        let results = vec![
            StoreErasureResult {
                store: "subscribers",
                status: StoreErasureStatus::Deleted,
                rows_affected: 3,
                error: None,
            },
            store_result("suppression_list", StoreErasureStatus::Retained("opt-out")),
        ];
        let cert = build_deletion_confirmation("req-1", "t1", "u@x.com", &results);
        assert_eq!(cert["overall"], "completed");
        assert_eq!(cert["records_deleted"], 3);
        assert!(cert["confirmation"]
            .as_str()
            .unwrap()
            .contains("as detailed per store"));
    }

    // ── A-3: redaction marker ───────────────────────────────────

    #[test]
    fn test_redact_marker_format() {
        let marker = redact_marker("user@example.com");
        assert!(marker.starts_with("erased+"));
        assert!(marker.ends_with("@invalid"));
        // Deterministic and non-reversible to the original email.
        assert_eq!(marker, redact_marker("user@example.com"));
        assert_ne!(marker, redact_marker("other@example.com"));
        assert!(!marker.contains("user@example.com"));
    }

    /// F9: the users tombstone marker must be tenant-unique — users.email is
    /// globally UNIQUE, so the same subject erased in two tenants needs two
    /// distinct tombstone emails.
    #[test]
    fn test_user_tombstone_marker_is_tenant_unique() {
        let a = user_tombstone_marker("user@example.com", "tenant_a");
        let b = user_tombstone_marker("user@example.com", "tenant_b");
        assert_ne!(a, b, "same subject in two tenants needs distinct markers");
        assert_eq!(a, user_tombstone_marker("user@example.com", "tenant_a"));
        assert!(!a.contains("user@example.com"));
        assert!(a.starts_with("erased+") && a.ends_with("@invalid"));
    }

    #[test]
    fn test_anonymize_json_text_replaces_email() {
        let doc = serde_json::json!({
            "customer_email": "user@example.com",
            "line_items": [
                {"buyer": "user@example.com", "amount": 10}
            ],
            "status": "paid",
        });
        let marker = redact_marker("user@example.com");
        let out = anonymize_json_text(doc, "user@example.com", &marker);
        let s = serde_json::to_string(&out).unwrap();
        assert!(!s.contains("user@example.com"));
        assert!(s.contains(&marker));
        assert_eq!(out["status"], "paid");
    }

    // ── F: retry decision ───────────────────────────────────────

    #[test]
    fn test_retry_decision_retries_then_fails() {
        assert_eq!(
            next_retry_decision(1),
            RetryDecision {
                attempt: 1,
                status: RetryStatus::Retrying
            }
        );
        assert_eq!(
            next_retry_decision(2),
            RetryDecision {
                attempt: 2,
                status: RetryStatus::Retrying
            }
        );
        // Third failure is terminal.
        assert_eq!(
            next_retry_decision(3),
            RetryDecision {
                attempt: 3,
                status: RetryStatus::Failed
            }
        );
        assert_eq!(
            next_retry_decision(9),
            RetryDecision {
                attempt: 9,
                status: RetryStatus::Failed
            }
        );
    }

    // ── G: export manifest ──────────────────────────────────────

    #[test]
    fn test_export_manifest_lists_all_stores_and_truncation() {
        let stores = vec![
            StoreExportResult::included("subscribers", 1),
            StoreExportResult::included("message_events", 250),
            StoreExportResult::skipped("tracking_events", &sqlx::Error::RowNotFound),
        ];
        let manifest = build_export_manifest(&stores, true);
        assert_eq!(manifest["truncated"], true);
        assert!(manifest["truncation_note"]
            .as_str()
            .unwrap()
            .contains("capped"));
        assert_eq!(manifest["stores"]["subscribers"]["records"], 1);
        assert_eq!(manifest["stores"]["tracking_events"]["included"], false);
        assert_eq!(manifest["stores"]["message_events"]["records"], 250);
    }

    #[test]
    fn test_export_manifest_not_truncated_by_default() {
        let manifest = build_export_manifest(&[], false);
        assert_eq!(manifest["truncated"], false);
    }

    // ── F: queue entry codec ────────────────────────────────────

    #[test]
    fn test_queue_entry_roundtrip() {
        let entry = encode_queue_entry("req-42");
        assert_eq!(decode_queue_entry(&entry), "req-42");
        // Legacy plain-string entries still decode.
        assert_eq!(decode_queue_entry("req-legacy"), "req-legacy");
    }

    #[test]
    fn test_queue_entry_staleness() {
        let old = serde_json::json!({
            "id": "req-old",
            "at": (Utc::now() - TimeDelta::try_seconds(600).unwrap()).to_rfc3339(),
        })
        .to_string();
        let fresh = serde_json::json!({
            "id": "req-fresh",
            "at": Utc::now().to_rfc3339(),
        })
        .to_string();
        let cutoff = Utc::now() - TimeDelta::try_seconds(300).unwrap();
        assert!(queue_entry_is_stale(&old, cutoff));
        assert!(!queue_entry_is_stale(&fresh, cutoff));
        // Legacy / malformed entries are treated as stale so the sweep
        // recovers them.
        assert!(queue_entry_is_stale("req-legacy", cutoff));
        assert!(queue_entry_is_stale("not json", cutoff));
    }

    // ── I-3: retention cutoffs ──────────────────────────────────

    #[test]
    fn test_retention_cutoffs_use_export_window_for_exports() {
        let now = Utc::now();
        let (consent_cutoff, export_cutoff) = retention_cutoffs(now, 730, 7);
        assert_eq!(consent_cutoff, now - Duration::days(730));
        assert_eq!(export_cutoff, now - Duration::days(7));
    }
}
#[test]
fn gdpr_requests_mirror_id_fits_varchar_26() {
    // The CP gdpr_requests.id column is VARCHAR(26): "gdr_" + 22 hex.
    let cp_request_id = format!("gdr_{}", &Uuid::new_v4().simple().to_string()[..22]);
    assert_eq!(cp_request_id.len(), 26);
    assert!(cp_request_id.starts_with("gdr_"));
}
