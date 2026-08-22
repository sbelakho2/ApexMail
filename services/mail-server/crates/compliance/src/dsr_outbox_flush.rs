//! DSR verification-outbox flush job — turns pending
//! `dsr_verification_outbox` rows into real mail.
//!
//! [`GdprAutomation::submit_request`](crate::gdpr_automation::GdprAutomation)
//! writes the raw verification token to the outbox transactionally with the
//! request; this module is the delivery half. It follows the platform's
//! system-email path (`api-server/src/routes/system_sender.rs`, the sales
//! dispatcher, enterprise `SupportNotifier`): insert a `messages` audit row
//! plus an `email_queue` row under the platform's verified system sender
//! domain, and let the delivery worker do the actual sending.
//!
//! Correctness properties:
//!
//! * **Transactional handoff** — the `email_queue` insert and the
//!   `status='sent'` outbox update commit in ONE transaction per row, so a
//!   row is either queued-and-sent or neither (no lost token, no phantom
//!   "sent" marker).
//! * **At-most-once queuing** — the sent-guard `UPDATE … WHERE status =
//!   'pending'` makes a concurrent flusher's transaction roll back its
//!   already-inserted queue row instead of double-queueing.
//! * **Bounded + retried** — each tick queues at most
//!   `COMPLIANCE_DSR_FLUSH_BATCH` oldest rows; a per-row failure increments
//!   `attempts` and is retried on the next tick until
//!   `COMPLIANCE_DSR_FLUSH_MAX_ATTEMPTS`, after which the row is marked
//!   `failed` (and eventually purged by the retention sweep with the
//!   request window).
//! * **No sender, no burn** — when the system sender domain is not
//!   DKIM/SES-ready the tick is skipped WITHOUT incrementing attempts: that
//!   is an infrastructure condition, not a per-row delivery failure.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::GdprConfig;
use crate::gdpr_automation::DsrOutboxEntry;

/// Platform system tenant — MUST stay in sync with
/// `api-server/src/routes/system_sender.rs` (`SYSTEM_TENANT_ID`). The
/// verified `domains` row for this tenant + [`SYSTEM_DOMAIN`] is what the
/// worker's `get_domain` authorization check resolves.
pub const SYSTEM_TENANT_ID: &str = "system_internal_tenant01";

/// Platform system sending domain — MUST stay in sync with
/// `api-server/src/routes/system_sender.rs` (`SYSTEM_DOMAIN`).
pub const SYSTEM_DOMAIN: &str = "apexmail.ee";

/// The verified system sender domain the flush job queues under.
#[derive(Debug, Clone)]
struct SystemSender {
    domain_id: Uuid,
}

/// Outcome of one flush tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushSummary {
    /// Rows queued into `email_queue` and marked sent.
    pub queued: usize,
    /// Rows whose queuing failed (attempts incremented; `failed` at cap).
    pub failed: usize,
    /// Pending rows were visible but the system sender domain was not ready —
    /// nothing was queued and no attempts were burned.
    pub skipped_sender_not_ready: bool,
}

/// Flushes the DSR verification outbox into `email_queue`.
pub struct DsrOutboxFlusher {
    db: PgPool,
    config: GdprConfig,
}

impl DsrOutboxFlusher {
    pub fn new(db: PgPool, config: GdprConfig) -> Self {
        Self { db, config }
    }

    /// Whether the deployment's mail transport requires SES-verified domains.
    /// Mirrors `apexmail_lib::transport::email_transport_is_ses`: only an
    /// explicit `smtp` (trimmed, case-insensitive) selects SMTP; unset,
    /// empty, `ses`, `self-hosted`, … all mean SES.
    fn ses_transport_required() -> bool {
        !matches!(
            std::env::var("EMAIL_TRANSPORT_TYPE")
                .ok()
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("smtp")
        )
    }

    /// Resolve the ready system sender domain — the same readiness predicate
    /// `api-server`'s system sender uses (SQL-level share; the worker
    /// re-validates DKIM/SES before sending). `None` means the platform
    /// cannot send system mail right now.
    async fn resolve_system_sender(&self) -> Result<Option<SystemSender>, String> {
        let requires_ses = Self::ses_transport_required();
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM domains \
             WHERE tenant_id = $1 AND name = $2 \
               AND status = 'verified' \
               AND dkim_enabled = true \
               AND dkim_selector IS NOT NULL \
               AND dkim_public_key IS NOT NULL \
               AND dkim_private_key IS NOT NULL \
               AND dkim_private_key LIKE 'dkim:v1:%' \
               AND ($3::boolean = false OR ses_verified = true) \
             LIMIT 1",
        )
        .bind(SYSTEM_TENANT_ID)
        .bind(SYSTEM_DOMAIN)
        .bind(requires_ses)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error (system sender lookup): {e}"))?;
        Ok(row.map(|(domain_id,)| SystemSender { domain_id }))
    }

    /// Oldest pending rows below the attempts cap, bounded by the batch size.
    async fn pending_batch(&self) -> Result<Vec<DsrOutboxEntry>, String> {
        sqlx::query_as(
            "SELECT id, request_id, tenant_id, email, verification_token, \
                    verify_url, status, attempts, created_at, sent_at \
             FROM dsr_verification_outbox \
             WHERE status = 'pending' AND attempts < $1 \
             ORDER BY created_at \
             LIMIT $2",
        )
        .bind(self.config.outbox_flush_max_attempts)
        .bind(self.config.outbox_flush_batch)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error (dsr outbox batch): {e}"))
    }

    /// One flush tick. Never errors wholesale: infrastructure failures are
    /// reported via [`FlushSummary`] so a cron caller can log-and-retry the
    /// next tick without losing the batch.
    pub async fn flush_once(&self) -> Result<FlushSummary, String> {
        let pending = self.pending_batch().await?;
        if pending.is_empty() {
            return Ok(FlushSummary {
                queued: 0,
                failed: 0,
                skipped_sender_not_ready: false,
            });
        }

        let Some(sender) = self.resolve_system_sender().await? else {
            warn!(
                count = pending.len(),
                "DSR outbox flush skipped: system sender domain {SYSTEM_DOMAIN} is not ready"
            );
            return Ok(FlushSummary {
                queued: 0,
                failed: 0,
                skipped_sender_not_ready: true,
            });
        };

        let mut summary = FlushSummary {
            queued: 0,
            failed: 0,
            skipped_sender_not_ready: false,
        };
        for entry in &pending {
            match self.queue_entry(entry, &sender).await {
                Ok(true) => summary.queued += 1,
                Ok(false) => {} // claimed concurrently — nothing to do
                Err(e) => {
                    warn!(
                        outbox_id = %entry.id,
                        request_id = %entry.request_id,
                        error = %e,
                        "Failed to queue DSR verification email"
                    );
                    self.record_failure(entry).await?;
                    summary.failed += 1;
                }
            }
        }
        Ok(summary)
    }

    /// Queue one entry: `messages` + `email_queue` inserts and the
    /// `status='sent'` guard in a single transaction. Returns `Ok(false)`
    /// when another flusher already claimed the row.
    async fn queue_entry(
        &self,
        entry: &DsrOutboxEntry,
        sender: &SystemSender,
    ) -> Result<bool, String> {
        let (subject, text, html) =
            dsr_verification_email(entry, self.config.request_expiration_days);
        let message_id = Uuid::new_v4();
        let now = Utc::now();
        let from = self.config.system_from_address.trim();
        let tags = vec!["dsr-verification".to_string()];
        let metadata = serde_json::json!({
            "source": "compliance-dsr-outbox",
            "outbox_id": entry.id,
            "request_id": entry.request_id,
            // Authoritative DSR tenant attribution (the queue row itself is
            // attributed to the platform system tenant, like every system
            // email).
            "dsr_tenant": entry.tenant_id,
        });

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB error (tx begin): {e}"))?;

        // Message audit row — same shape as api-server's system emails.
        sqlx::query(
            "INSERT INTO messages \
                 (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, tags, created_at) \
             VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, 'queued', $8::jsonb, NOW())",
        )
        .bind(message_id)
        .bind(SYSTEM_TENANT_ID)
        .bind(from)
        .bind(serde_json::json!([entry.email]))
        .bind(&subject)
        .bind(&html)
        .bind(&text)
        .bind(serde_json::json!(tags))
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error (messages): {e}"))?;

        // Queue row — BOTH column families, mirroring the platform's
        // system-email insert (the worker reads "from"/"to"/html/text).
        sqlx::query(
            "INSERT INTO email_queue (\
                id, message_id, tenant_id, domain_id, from_address, to_addresses, subject, \
                \"from\", \"to\", html, text, tags, metadata, scheduled_at, priority, status, created_at, updated_at\
             ) VALUES (\
                $1, $2, $3, $4::uuid, $5, ARRAY[$6], $7, \
                $5, $6, $8, $9, $10, $11, $12, 5, 'pending', $13, $13\
             )",
        )
        .bind(Uuid::new_v4())
        .bind(message_id)
        .bind(SYSTEM_TENANT_ID)
        .bind(sender.domain_id)
        .bind(from)
        .bind(&entry.email)
        .bind(&subject)
        .bind(&html)
        .bind(&text)
        .bind(&tags)
        .bind(&metadata)
        .bind(Option::<chrono::DateTime<Utc>>::None)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error (email_queue): {e}"))?;

        // Sent-guard LAST: under READ COMMITTED a concurrent flusher blocks
        // here until the first commits, then matches zero rows — and this
        // transaction (including its queue insert) rolls back.
        let claimed = sqlx::query(
            "UPDATE dsr_verification_outbox \
             SET status = 'sent', sent_at = NOW() \
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(&entry.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB error (mark sent): {e}"))?;

        if claimed.rows_affected() != 1 {
            // Another flusher won the race — roll the inserts back.
            tx.rollback()
                .await
                .map_err(|e| format!("DB error (rollback): {e}"))?;
            return Ok(false);
        }

        tx.commit()
            .await
            .map_err(|e| format!("DB error (commit): {e}"))?;
        info!(
            outbox_id = %entry.id,
            request_id = %entry.request_id,
            "DSR verification email queued for delivery"
        );
        Ok(true)
    }

    /// Increment `attempts`; at the cap, park the row as `failed` so it stops
    /// being retried (the retention sweep purges it with the request window).
    async fn record_failure(&self, entry: &DsrOutboxEntry) -> Result<(), String> {
        sqlx::query(
            "UPDATE dsr_verification_outbox \
             SET attempts = attempts + 1, \
                 status = CASE WHEN attempts + 1 >= $2 THEN 'failed' ELSE status END \
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(&entry.id)
        .bind(self.config.outbox_flush_max_attempts)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error (attempts increment): {e}"))?;
        Ok(())
    }
}

/// The verification email for one outbox entry: (subject, plain text, HTML).
/// Pure function — unit-tested below. The stored `verify_url` identifies the
/// request; the raw token is what completes verification, so both are in the
/// body and the token never appears in API responses or logs.
pub fn dsr_verification_email(
    entry: &DsrOutboxEntry,
    request_expiration_days: i64,
) -> (String, String, String) {
    let expires = (entry.created_at + Duration::days(request_expiration_days))
        .format("%Y-%m-%d")
        .to_string();

    let subject = "Verify your ApexMail data request".to_string();

    let text = format!(
        "Hello,\n\
         \n\
         We received a data-subject request for this email address on ApexMail.\n\
         To confirm the request, open the verification link and enter this code:\n\
         \n\
         Link: {url}\n\
         Code: {token}\n\
         \n\
         The request expires on {expires}. If you did not submit this request,\n\
         ignore this email — nothing will happen without the code.\n\
         \n\
         — ApexMail",
        url = entry.verify_url,
        token = entry.verification_token,
        expires = expires,
    );

    let html = format!(
        "<html><body style=\"font-family:sans-serif;line-height:1.5\">\
         <p>Hello,</p> \
         <p>We received a data-subject request for this email address on ApexMail. \
         To confirm the request, open the verification link and enter this code:</p> \
         <p><a href=\"{url}\">{url}</a></p> \
         <p>Code: <code>{token}</code></p> \
         <p>The request expires on {expires}. If you did not submit this request, \
         ignore this email — nothing will happen without the code.</p> \
         <p>— ApexMail</p> \
         </body></html>",
        url = html_escape(&entry.verify_url),
        token = html_escape(&entry.verification_token),
        expires = html_escape(&expires),
    );

    (subject, text, html)
}

/// Minimal HTML escaping for the token/URL interpolation above.
fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn entry(url: &str, token: &str) -> DsrOutboxEntry {
        DsrOutboxEntry {
            id: "outbox-1".into(),
            request_id: "req-1".into(),
            tenant_id: "tenant-1".into(),
            email: "subject@example.com".into(),
            verification_token: token.into(),
            verify_url: url.into(),
            status: "pending".into(),
            attempts: 0,
            created_at: Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap(),
            sent_at: None,
        }
    }

    #[test]
    fn system_sender_constants_match_the_api_server() {
        // The flush job queues under the SAME system identity api-server's
        // system_sender uses — drift here means the worker's domain check
        // rejects every queued row.
        assert_eq!(SYSTEM_TENANT_ID, "system_internal_tenant01");
        assert_eq!(SYSTEM_DOMAIN, "apexmail.ee");
    }

    #[test]
    fn email_carries_url_and_raw_token() {
        let (subject, text, html) = dsr_verification_email(
            &entry("https://gdpr.apexmail.ee/gdpr/verify/abc", "tok-123"),
            30,
        );
        assert_eq!(subject, "Verify your ApexMail data request");
        // Both parts of the verification (link + code) are in both bodies.
        assert!(text.contains("https://gdpr.apexmail.ee/gdpr/verify/abc"));
        assert!(text.contains("tok-123"));
        assert!(html.contains("https://gdpr.apexmail.ee/gdpr/verify/abc"));
        assert!(html.contains("tok-123"));
        // Expiry is derived from request_expiration_days + created_at.
        assert!(text.contains("2026-09-20"), "30 days after 2026-08-21");
    }

    #[test]
    fn email_html_escapes_hostile_token_and_url() {
        let hostile = entry(
            "https://gdpr.apexmail.ee/gdpr/verify/a\"b",
            "<script>alert(1)</script>",
        );
        let (_, _, html) = dsr_verification_email(&hostile, 30);
        assert!(!html.contains("<script>"), "raw markup must not survive");
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&quot;"));
    }

    #[test]
    fn ses_transport_required_mirrors_the_shared_helper() {
        // Mirrors apexmail_lib::transport::email_transport_is_ses semantics:
        // only an explicit (trimmed, case-insensitive) "smtp" selects SMTP.
        let cases = [
            (None, true),
            (Some(""), true),
            (Some("ses"), true),
            (Some("SES"), true),
            (Some("self-hosted"), true),
            (Some("direct"), true),
            (Some("smtp"), false),
            (Some(" SMTP "), false),
            (Some("Smtp"), false),
        ];
        for (value, expected) in cases {
            // SAFETY: single-threaded assertion over a process-global env
            // var; tests touching it run serially within this module.
            match value {
                Some(v) => std::env::set_var("EMAIL_TRANSPORT_TYPE", v),
                None => std::env::remove_var("EMAIL_TRANSPORT_TYPE"),
            }
            assert_eq!(
                DsrOutboxFlusher::ses_transport_required(),
                expected,
                "{value:?}"
            );
        }
        std::env::remove_var("EMAIL_TRANSPORT_TYPE");
    }
}
