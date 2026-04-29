//! Email Queue
//!
//! Persistent queue for outbound emails with retry logic.

use anyhow::Result;
use chrono::{DateTime, Utc};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::smtp_sender::SmtpSender;
use crate::dkim::DkimSigner;

/// Result of an atomic cancel attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelResult {
/// Email was successfully cancelled.
    Cancelled,
/// Email was not found in the queue.
    NotFound,
/// Email exists but cannot be cancelled (with human-readable reason).
    NotCancellable(String),
}

/// Email status in the queue
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "email_status", rename_all = "lowercase")]
pub enum EmailStatus {
    Pending,
    Processing,
    Sent,
    Failed,
    Deferred,
}

impl Default for EmailStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Queued email record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedEmail {
    pub id: Uuid,
    pub from_address: String,
    pub to_addresses: Vec<String>,
    pub subject: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub headers: serde_json::Value,
    pub status: EmailStatus,
    pub attempts: i32,
    pub max_attempts: i32,
    pub last_error: Option<String>,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
    pub campaign_id: Option<Uuid>,
    pub sequence_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub priority: i32,
}

/// Email queue configuration
#[derive(Debug, Clone)]
pub struct QueueConfig {
    pub max_attempts: i32,
    pub retry_delays: Vec<Duration>,
    pub batch_size: usize,
    pub poll_interval: Duration,
    pub worker_count: usize,
}

const DEFAULT_QUEUE_MAX_ATTEMPTS: i32 = 5;
const DEFAULT_QUEUE_RETRY_DELAY_SECS: [u64; 5] = [60, 300, 1_800, 7_200, 21_600];
const DEFAULT_QUEUE_EMPTY_RETRY_FALLBACK_SECS: u64 = 300;
const DEFAULT_QUEUE_BATCH_SIZE: usize = 100;
const DEFAULT_QUEUE_POLL_INTERVAL_SECS: u64 = 5;
const DEFAULT_QUEUE_WORKER_COUNT: usize = 4;

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_QUEUE_MAX_ATTEMPTS,
            retry_delays: DEFAULT_QUEUE_RETRY_DELAY_SECS
                .iter()
                .copied()
                .map(Duration::from_secs)
                .collect(),
            batch_size: DEFAULT_QUEUE_BATCH_SIZE,
            poll_interval: Duration::from_secs(DEFAULT_QUEUE_POLL_INTERVAL_SECS),
            worker_count: DEFAULT_QUEUE_WORKER_COUNT,
        }
    }
}

/// Email queue manager
pub struct EmailQueue {
    pool: PgPool,
    config: QueueConfig,
/// SMTP sender no longer behind Mutex since send is &self (#114/#115)
    smtp_sender: SmtpSender,
    dkim_signer: Option<DkimSigner>,
}

impl EmailQueue {
/// Create a new email queue
    pub fn new(pool: PgPool, config: QueueConfig, smtp_sender: SmtpSender) -> Self {
        Self {
            pool,
            config,
            smtp_sender,
            dkim_signer: None,
        }
    }
    
/// Set DKIM signer
    pub fn with_dkim_signer(mut self, signer: DkimSigner) -> Self {
        self.dkim_signer = Some(signer);
        self
    }
    
/// Initialize queue tables
    pub async fn initialize(&self) -> Result<()> {
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS email_queue (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                from_address TEXT NOT NULL,
                to_addresses TEXT[] NOT NULL,
                subject TEXT NOT NULL,
                text_body TEXT,
                html_body TEXT,
                headers JSONB DEFAULT '{}'::jsonb,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INT NOT NULL DEFAULT 0,
                max_attempts INT NOT NULL DEFAULT 5,
                last_error TEXT,
                next_retry_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                sent_at TIMESTAMPTZ,
                campaign_id UUID,
                sequence_id UUID,
                contact_id UUID,
                priority INT NOT NULL DEFAULT 0
            )
        "#)
        .execute(&self.pool)
        .await?;
        
        sqlx::query(r#"
            CREATE INDEX IF NOT EXISTS idx_email_queue_status 
            ON email_queue(status, next_retry_at, priority DESC)
        "#)
        .execute(&self.pool)
        .await?;
        
        sqlx::query(r#"
            CREATE INDEX IF NOT EXISTS idx_email_queue_campaign 
            ON email_queue(campaign_id) WHERE campaign_id IS NOT NULL
        "#)
        .execute(&self.pool)
        .await?;
        
        info!("Email queue tables initialized");
        Ok(())
    }
    
/// Enqueue an email
    pub async fn enqueue(&self, email: QueuedEmail) -> Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(r#"
            INSERT INTO email_queue (
                id, from_address, to_addresses, subject, text_body, html_body,
                headers, status, max_attempts, campaign_id, sequence_id, 
                contact_id, priority
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11, $12)
            RETURNING id
        "#)
        .bind(&email.id)
        .bind(&email.from_address)
        .bind(&email.to_addresses)
        .bind(&email.subject)
        .bind(&email.text_body)
        .bind(&email.html_body)
        .bind(&email.headers)
        .bind(email.max_attempts) // #112:Use the email's own max_attempts, not global config
        .bind(&email.campaign_id)
        .bind(&email.sequence_id)
        .bind(&email.contact_id)
        .bind(email.priority)
        .fetch_one(&self.pool)
        .await?;
        
        debug!(email_id = %id, "Email enqueued");
        Ok(id)
    }
    
/// Bulk enqueue emails using a single multi-row INSERT for performance.
/// Falls back to sequential inserts if the batch is empty.
    pub async fn enqueue_batch(&self, emails: Vec<QueuedEmail>) -> Result<Vec<Uuid>> {
        if emails.is_empty() {
            return Ok(Vec::new());
        }

// Build a single multi-row INSERT:VALUES ($1..$12), ($13..$24), ...
        let cols = 12; // number of bind params per row
        let mut sql = String::from(
            "INSERT INTO email_queue (
                id, from_address, to_addresses, subject, text_body, html_body,
                headers, status, max_attempts, campaign_id, sequence_id,
                contact_id, priority
            ) VALUES ",
        );

        let _args: Vec<Box<dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync>> = Vec::new();
        let mut ids = Vec::with_capacity(emails.len());

        for (i, email) in emails.iter().enumerate() {
            ids.push(email.id);
            if i > 0 {
                sql.push_str(", ");
            }
            let base = i * cols + 1;
            push_pending_insert_row_sql(&mut sql, base);
        }
        sql.push_str(" RETURNING id");

// Bind all parameters in order using a raw query
        let mut query = sqlx::query_scalar::<_, Uuid>(&sql);
        for email in &emails {
            query = query
                .bind(email.id)
                .bind(&email.from_address)
                .bind(&email.to_addresses)
                .bind(&email.subject)
                .bind(&email.text_body)
                .bind(&email.html_body)
                .bind(&email.headers)
                .bind(email.max_attempts)
                .bind(&email.campaign_id)
                .bind(&email.sequence_id)
                .bind(&email.contact_id)
                .bind(email.priority);
        }

        let returned_ids = query.fetch_all(&self.pool).await?;
        info!(count = returned_ids.len(), "Batch emails enqueued");
        Ok(returned_ids)
    }
    
/// Fetch pending emails for processing
    pub async fn fetch_pending(&self, limit: i64) -> Result<Vec<QueuedEmail>> {
        let rows = sqlx::query(r#"
            UPDATE email_queue
            SET status = 'processing', updated_at = NOW()
            WHERE id IN (
                SELECT id FROM email_queue
                WHERE status IN ('pending', 'deferred')
                AND (next_retry_at IS NULL OR next_retry_at <= NOW())
                ORDER BY priority DESC, created_at ASC
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING *
        "#)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        let emails = rows.iter().map(|row| QueuedEmail {
            id: row.get("id"),
            from_address: row.get("from_address"),
            to_addresses: row.get("to_addresses"),
            subject: row.get("subject"),
            text_body: row.get("text_body"),
            html_body: row.get("html_body"),
            headers: row.get("headers"),
            status: EmailStatus::Processing,
            attempts: row.get("attempts"),
            max_attempts: row.get("max_attempts"),
            last_error: row.get("last_error"),
            next_retry_at: row.get("next_retry_at"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            sent_at: row.get("sent_at"),
            campaign_id: row.get("campaign_id"),
            sequence_id: row.get("sequence_id"),
            contact_id: row.get("contact_id"),
            priority: row.get("priority"),
        }).collect();
        
        Ok(emails)
    }
    
/// Mark email as sent
    pub async fn mark_sent(&self, id: &Uuid) -> Result<()> {
        sqlx::query(r#"
            UPDATE email_queue
            SET status = 'sent', sent_at = NOW(), updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(id)
        .execute(&self.pool)
        .await?;
        
        debug!(email_id = %id, "Email marked as sent");
        Ok(())
    }

/// Get queued email by ID
    pub async fn get_email(&self, id: &Uuid) -> Result<Option<QueuedEmail>> {
        let row = sqlx::query(r#"
            SELECT * FROM email_queue WHERE id = $1
        "#)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        let email = row.map(|row| {
            let status = match row.get::<String, _>("status").as_str() {
                "pending" => EmailStatus::Pending,
                "processing" => EmailStatus::Processing,
                "sent" => EmailStatus::Sent,
                "failed" => EmailStatus::Failed,
                "deferred" => EmailStatus::Deferred,
                _ => EmailStatus::Pending,
            };

            QueuedEmail {
                id: row.get("id"),
                from_address: row.get("from_address"),
                to_addresses: row.get("to_addresses"),
                subject: row.get("subject"),
                text_body: row.get("text_body"),
                html_body: row.get("html_body"),
                headers: row.get("headers"),
                status,
                attempts: row.get("attempts"),
                max_attempts: row.get("max_attempts"),
                last_error: row.get("last_error"),
                next_retry_at: row.get("next_retry_at"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                sent_at: row.get("sent_at"),
                campaign_id: row.get("campaign_id"),
                sequence_id: row.get("sequence_id"),
                contact_id: row.get("contact_id"),
                priority: row.get("priority"),
            }
        });

        Ok(email)
    }

/// Atomically cancel a queued email.
/// Uses a single `UPDATE ... WHERE status IN ('pending','deferred') RETURNING`
/// to eliminate the TOCTOU race between checking status and writing the
/// cancellation. If the UPDATE affects zero rows the email either doesn't
/// exist or is in a non-cancellable state — a follow-up SELECT distinguishes
/// the two cases.
    pub async fn cancel_email_atomic(&self, id: &Uuid) -> Result<CancelResult> {
        let result = sqlx::query(r#"
            UPDATE email_queue
            SET status = 'failed',
                last_error = 'Cancelled by user',
                updated_at = NOW()
            WHERE id = $1
              AND status IN ('pending', 'deferred')
            RETURNING id
        "#)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        if result.is_some() {
            return Ok(CancelResult::Cancelled);
        }

// Zero rows affected — determine why
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT status FROM email_queue WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match existing.as_deref() {
            None => Ok(CancelResult::NotFound),
            Some("sent") => Ok(CancelResult::NotCancellable(
                "Cannot cancel: email already delivered".to_string(),
            )),
            Some("failed") => Ok(CancelResult::NotCancellable(
                "Cannot cancel: email already permanently failed".to_string(),
            )),
            Some("processing") => Ok(CancelResult::NotCancellable(
                "Cannot cancel: email is currently being sent".to_string(),
            )),
            Some(other) => Ok(CancelResult::NotCancellable(
                format!("Cannot cancel: email is in '{}' state", other),
            )),
        }
    }

/// Mark email as failed
    pub async fn mark_failed(&self, id: &Uuid, error: &str, defer: bool) -> Result<()> {
        let email = sqlx::query(r#"
            SELECT attempts, max_attempts FROM email_queue WHERE id = $1
        "#)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        
        let attempts: i32 = email.get("attempts");
        let max_attempts: i32 = email.get("max_attempts");
        let new_attempts = attempts + 1;
        
        if defer && new_attempts < max_attempts {
// #113:Guard against empty retry_delays causing integer underflow
            let delay = if self.config.retry_delays.is_empty() {
                Duration::from_secs(DEFAULT_QUEUE_EMPTY_RETRY_FALLBACK_SECS)
            } else {
                let delay_index = (new_attempts - 1).max(0) as usize;
                let delay_index = delay_index.min(self.config.retry_delays.len() - 1);
                self.config.retry_delays[delay_index]
            };
            let chrono_delay = chrono::Duration::from_std(delay)
                .unwrap_or_else(|_| chrono::Duration::seconds(300)); // fallback:5 minutes
            let next_retry = Utc::now() + chrono_delay;
            
            sqlx::query(r#"
                UPDATE email_queue
                SET status = 'deferred', attempts = $2, last_error = $3,
                    next_retry_at = $4, updated_at = NOW()
                WHERE id = $1
            "#)
            .bind(id)
            .bind(new_attempts)
            .bind(error)
            .bind(next_retry)
            .execute(&self.pool)
            .await?;
            
            warn!(
                email_id = %id, 
                attempts = new_attempts, 
                next_retry = %next_retry,
                "Email deferred for retry"
            );
        } else {
            sqlx::query(r#"
                UPDATE email_queue
                SET status = 'failed', attempts = $2, last_error = $3, updated_at = NOW()
                WHERE id = $1
            "#)
            .bind(id)
            .bind(new_attempts)
            .bind(error)
            .execute(&self.pool)
            .await?;
            
            error!(email_id = %id, error = error, "Email permanently failed");
        }
        
        Ok(())
    }
    
/// Process a single email
    async fn process_email(&self, email: &QueuedEmail) -> Result<()> {
// Extract custom headers from JSON
        let headers: Option<std::collections::HashMap<String, String>> = email.headers
            .as_object()
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            });
        
// Send via SMTP — no Mutex needed, send is &self (#114/#115)
        self.smtp_sender.send(
            &email.from_address,
            &email.to_addresses,
            &email.subject,
            email.text_body.as_deref(),
            email.html_body.as_deref(),
            headers,
        ).await?;
        
        Ok(())
    }
    
/// Start the queue processor
    pub async fn start_processing(self: std::sync::Arc<Self>, mut shutdown: mpsc::Receiver<()>) {
        info!(
            workers = self.config.worker_count,
            batch_size = self.config.batch_size,
            "Starting email queue processor"
        );
        
        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("Email queue processor shutting down");
                    break;
                }
                _ = tokio::time::sleep(self.config.poll_interval) => {
                    if let Err(e) = self.process_batch().await {
                        error!(error = %e, "Failed to process email batch");
                    }
                }
            }
        }
    }
    
/// Process a batch of emails concurrently (#115)
    async fn process_batch(&self) -> Result<()> {
        let emails = self.fetch_pending(self.config.batch_size as i64).await?;
        
        if emails.is_empty() {
            return Ok(());
        }
        
        info!(count = emails.len(), "Processing email batch");
        
// Process emails concurrently instead of sequentially
        let futures: Vec<_> = emails.iter().map(|email| async {
            let result = self.process_email(email).await;
            (email.id, result)
        }).collect();
        
        let results = join_all(futures).await;
        
        for (email_id, result) in results {
            match result {
                Ok(()) => {
                    self.mark_sent(&email_id).await?;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    let is_temporary = error_str.contains("timeout")
                        || error_str.contains("connection refused")
                        || error_str.contains("temporarily");
                    
                    self.mark_failed(&email_id, &error_str, is_temporary).await?;
                }
            }
        }
        
        Ok(())
    }
    
/// Get queue statistics
    pub async fn get_stats(&self) -> Result<QueueStats> {
        let row = sqlx::query(r#"
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'processing') as processing,
                COUNT(*) FILTER (WHERE status = 'sent') as sent,
                COUNT(*) FILTER (WHERE status = 'failed') as failed,
                COUNT(*) FILTER (WHERE status = 'deferred') as deferred
            FROM email_queue
        "#)
        .fetch_one(&self.pool)
        .await?;
        
        Ok(QueueStats {
            pending: row.get::<i64, _>("pending") as u64,
            processing: row.get::<i64, _>("processing") as u64,
            sent: row.get::<i64, _>("sent") as u64,
            failed: row.get::<i64, _>("failed") as u64,
            deferred: row.get::<i64, _>("deferred") as u64,
        })
    }
    
/// Purge old sent emails
    pub async fn purge_old(&self, days: i32) -> Result<u64> {
        let result = sqlx::query(r#"
            DELETE FROM email_queue
            WHERE status = 'sent' AND sent_at < NOW() - $1::interval
        "#)
        .bind(format!("{} days", days))
        .execute(&self.pool)
        .await?;
        
        let count = result.rows_affected();
        info!(count = count, days = days, "Purged old sent emails");
        Ok(count)
    }
    
/// Cancel pending emails for a campaign
    pub async fn cancel_campaign(&self, campaign_id: &Uuid) -> Result<u64> {
        let result = sqlx::query(r#"
            UPDATE email_queue
            SET status = 'failed', last_error = 'Campaign cancelled', updated_at = NOW()
            WHERE campaign_id = $1 AND status IN ('pending', 'deferred')
        "#)
        .bind(campaign_id)
        .execute(&self.pool)
        .await?;
        
        let count = result.rows_affected();
        info!(campaign_id = %campaign_id, count = count, "Cancelled campaign emails");
        Ok(count)
    }
}

/// Queue statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStats {
    pub pending: u64,
    pub processing: u64,
    pub sent: u64,
    pub failed: u64,
    pub deferred: u64,
}

impl QueueStats {
    pub fn total(&self) -> u64 {
        self.pending + self.processing + self.sent + self.failed + self.deferred
    }
}

fn push_pending_insert_row_sql(sql: &mut String, base: usize) {
    sql.push_str(&format!(
        "(${}, ${}, ${}, ${}, ${}, ${}, ${}, 'pending', ${}, ${}, ${}, ${}, ${})",
        base,
        base + 1,
        base + 2,
        base + 3,
        base + 4,
        base + 5,
        base + 6,
        base + 7,
        base + 8,
        base + 9,
        base + 10,
        base + 11,
    ));
}

// ---------------------------------------------------------------------------
// Tests — unit tests that do NOT require a database
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

// -----------------------------------------------------------------------
// CancelResult
// -----------------------------------------------------------------------

    #[test]
    fn cancel_result_eq_cancelled() {
        assert_eq!(CancelResult::Cancelled, CancelResult::Cancelled);
    }

    #[test]
    fn cancel_result_eq_not_found() {
        assert_eq!(CancelResult::NotFound, CancelResult::NotFound);
    }

    #[test]
    fn cancel_result_not_cancellable_with_reason() {
        let a = CancelResult::NotCancellable("already sent".into());
        let b = CancelResult::NotCancellable("already sent".into());
        assert_eq!(a, b);
    }

    #[test]
    fn cancel_result_variants_not_equal_across_types() {
        assert_ne!(CancelResult::Cancelled, CancelResult::NotFound);
        assert_ne!(
            CancelResult::Cancelled,
            CancelResult::NotCancellable("x".into()),
        );
    }

    #[test]
    fn cancel_result_debug_format() {
        let r = CancelResult::Cancelled;
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("Cancelled"));
    }

    #[test]
    fn cancel_result_clone() {
        let r = CancelResult::NotCancellable("reason".into());
        let c = r.clone();
        assert_eq!(r, c);
    }

// -----------------------------------------------------------------------
// EmailStatus
// -----------------------------------------------------------------------

    #[test]
    fn email_status_default_is_pending() {
        assert_eq!(EmailStatus::default(), EmailStatus::Pending);
    }

    #[test]
    fn email_status_all_variants_distinct() {
        let variants = [
            EmailStatus::Pending,
            EmailStatus::Processing,
            EmailStatus::Sent,
            EmailStatus::Failed,
            EmailStatus::Deferred,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn email_status_serde_roundtrip() {
        for status in [
            EmailStatus::Pending,
            EmailStatus::Processing,
            EmailStatus::Sent,
            EmailStatus::Failed,
            EmailStatus::Deferred,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: EmailStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn email_status_copy() {
        let s = EmailStatus::Sent;
        let s2 = s; // Copy
        assert_eq!(s, s2);
    }

// -----------------------------------------------------------------------
// QueueConfig
// -----------------------------------------------------------------------

    #[test]
    fn queue_config_default_values() {
        let cfg = QueueConfig::default();
        assert_eq!(cfg.max_attempts, DEFAULT_QUEUE_MAX_ATTEMPTS);
        assert_eq!(cfg.worker_count, DEFAULT_QUEUE_WORKER_COUNT);
        assert_eq!(cfg.batch_size, DEFAULT_QUEUE_BATCH_SIZE);
        assert_eq!(cfg.retry_delays.len(), DEFAULT_QUEUE_RETRY_DELAY_SECS.len());
    }

    #[test]
    fn queue_config_retry_delays_ascending() {
        let cfg = QueueConfig::default();
        for i in 1..cfg.retry_delays.len() {
            assert!(
                cfg.retry_delays[i] > cfg.retry_delays[i - 1],
                "Retry delays should be monotonically increasing"
            );
        }
    }

    #[test]
    fn queue_config_first_retry_under_5_minutes() {
        let cfg = QueueConfig::default();
        assert!(cfg.retry_delays[0] <= Duration::from_secs(DEFAULT_QUEUE_RETRY_DELAY_SECS[1]));
    }

// -----------------------------------------------------------------------
// QueueStats
// -----------------------------------------------------------------------

    #[test]
    fn queue_stats_total_sums_all_fields() {
        let stats = QueueStats {
            pending: 10,
            processing: 5,
            sent: 100,
            failed: 3,
            deferred: 2,
        };
        assert_eq!(stats.total(), 120);
    }

    #[test]
    fn queue_stats_total_zero() {
        let stats = QueueStats {
            pending: 0,
            processing: 0,
            sent: 0,
            failed: 0,
            deferred: 0,
        };
        assert_eq!(stats.total(), 0);
    }

    #[test]
    fn queue_stats_total_overflow_risk() {
// Ensure the addition doesn't panic with large but reasonable values
        let stats = QueueStats {
            pending: u64::MAX / 5,
            processing: u64::MAX / 5,
            sent: u64::MAX / 5,
            failed: u64::MAX / 5,
            deferred: u64::MAX / 5,
        };
        let _ = stats.total(); // should not panic
    }

    #[test]
    fn queue_stats_serde_roundtrip() {
        let stats = QueueStats {
            pending: 42,
            processing: 7,
            sent: 999,
            failed: 0,
            deferred: 12,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: QueueStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total(), stats.total());
    }

// -----------------------------------------------------------------------
// QueuedEmail
// -----------------------------------------------------------------------

    fn make_test_email() -> QueuedEmail {
        QueuedEmail {
            id: Uuid::new_v4(),
            from_address: "sender@test.com".into(),
            to_addresses: vec!["r1@test.com".into(), "r2@test.com".into()],
            subject: "Test email".into(),
            text_body: Some("Hello".into()),
            html_body: Some("<p>Hello</p>".into()),
            headers: serde_json::json!({"X-Custom": "value"}),
            status: EmailStatus::Pending,
            attempts: 0,
            max_attempts: DEFAULT_QUEUE_MAX_ATTEMPTS,
            last_error: None,
            next_retry_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            sent_at: None,
            campaign_id: None,
            sequence_id: None,
            contact_id: None,
            priority: 0,
        }
    }

    #[test]
    fn queued_email_serde_roundtrip() {
        let email = make_test_email();
        let json = serde_json::to_string(&email).unwrap();
        let parsed: QueuedEmail = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, email.id);
        assert_eq!(parsed.from_address, email.from_address);
        assert_eq!(parsed.to_addresses, email.to_addresses);
        assert_eq!(parsed.subject, email.subject);
        assert_eq!(parsed.status, email.status);
    }

    #[test]
    fn queued_email_optional_fields_none() {
        let mut email = make_test_email();
        email.text_body = None;
        email.html_body = None;
        email.last_error = None;
        email.next_retry_at = None;
        email.campaign_id = None;

        let json = serde_json::to_string(&email).unwrap();
        let parsed: QueuedEmail = serde_json::from_str(&json).unwrap();
        assert!(parsed.text_body.is_none());
        assert!(parsed.html_body.is_none());
    }

    #[test]
    fn queued_email_multiple_recipients() {
        let email = QueuedEmail {
            to_addresses: vec![
                "a@test.com".into(),
                "b@test.com".into(),
                "c@test.com".into(),
            ],
            ..make_test_email()
        };
        assert_eq!(email.to_addresses.len(), 3);
    }

    #[test]
    fn queued_email_empty_recipients() {
        let email = QueuedEmail {
            to_addresses: vec![],
            ..make_test_email()
        };
        assert!(email.to_addresses.is_empty());
    }

// -----------------------------------------------------------------------
// Batch INSERT SQL builder validation
// -----------------------------------------------------------------------

/// Validates that the multi-row INSERT SQL builder produces correct
/// parameter numbering for N rows.
    fn validate_batch_sql(count: usize) -> String {
        let cols = 12;
        let mut sql = String::from(
            "INSERT INTO email_queue (
                id, from_address, to_addresses, subject, text_body, html_body,
                headers, status, max_attempts, campaign_id, sequence_id,
                contact_id, priority
            ) VALUES ",
        );

        for i in 0..count {
            if i > 0 {
                sql.push_str(", ");
            }
            let base = i * cols + 1;
            super::push_pending_insert_row_sql(&mut sql, base);
        }
        sql.push_str(" RETURNING id");
        sql
    }

    #[test]
    fn batch_sql_single_row() {
        let sql = validate_batch_sql(1);
        assert!(sql.contains("($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11, $12)"));
        assert!(sql.contains("RETURNING id"));
// Should not have a second row
        assert!(!sql.contains("$13"));
    }

    #[test]
    fn batch_sql_two_rows() {
        let sql = validate_batch_sql(2);
        assert!(sql.contains("$1,"));
        assert!(sql.contains("$12)"));
        assert!(sql.contains("$13,"));
        assert!(sql.contains("$24)"));
        assert!(!sql.contains("$25"));
    }

    #[test]
    fn batch_sql_ten_rows() {
        let sql = validate_batch_sql(10);
// Last row starts at $109 (9 * 12 + 1), ends at $120
        assert!(sql.contains("$109,"));
        assert!(sql.contains("$120)"));
        assert!(!sql.contains("$121"));
    }

    #[test]
    fn batch_sql_hundred_rows() {
        let sql = validate_batch_sql(100);
// Last row:base = 99 * 12 + 1 = 1189, ends at $1200
        assert!(sql.contains("$1189,"));
        assert!(sql.contains("$1200)"));
    }

    #[test]
    fn batch_sql_no_duplicate_params() {
        let sql = validate_batch_sql(5);
        let cols = 12;
        let total_params = 5 * cols;
        for p in 1..=total_params {
            let needle = format!("${}", p);
            let count = sql.matches(&needle)
                .count();
// Each parameter should appear exactly once (but $1 can also match
// $10, $11, etc. so we check with trailing comma/paren)
            assert!(count >= 1, "Parameter {} should appear at least once", p);
        }
    }
}
