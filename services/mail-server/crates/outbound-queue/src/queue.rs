//! Email Queue
//!
//! Persistent queue for outbound emails with retry logic.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::smtp_sender::SmtpSender;
use crate::dkim::DkimSigner;

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

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            retry_delays: vec![
                Duration::from_secs(60),        // 1 minute
                Duration::from_secs(300),       // 5 minutes
                Duration::from_secs(1800),      // 30 minutes
                Duration::from_secs(7200),      // 2 hours
                Duration::from_secs(21600),     // 6 hours
            ],
            batch_size: 100,
            poll_interval: Duration::from_secs(5),
            worker_count: 4,
        }
    }
}

/// Email queue manager
pub struct EmailQueue {
    pool: PgPool,
    config: QueueConfig,
    smtp_sender: tokio::sync::Mutex<SmtpSender>,
    dkim_signer: Option<DkimSigner>,
}

impl EmailQueue {
    /// Create a new email queue
    pub fn new(pool: PgPool, config: QueueConfig, smtp_sender: SmtpSender) -> Self {
        Self {
            pool,
            config,
            smtp_sender: tokio::sync::Mutex::new(smtp_sender),
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
        .bind(self.config.max_attempts)
        .bind(&email.campaign_id)
        .bind(&email.sequence_id)
        .bind(&email.contact_id)
        .bind(email.priority)
        .fetch_one(&self.pool)
        .await?;
        
        debug!(email_id = %id, "Email enqueued");
        Ok(id)
    }
    
    /// Bulk enqueue emails
    pub async fn enqueue_batch(&self, emails: Vec<QueuedEmail>) -> Result<Vec<Uuid>> {
        let mut ids = Vec::with_capacity(emails.len());
        
        for email in emails {
            let id = self.enqueue(email).await?;
            ids.push(id);
        }
        
        info!(count = ids.len(), "Batch emails enqueued");
        Ok(ids)
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
            let delay_index = (new_attempts - 1).min(self.config.retry_delays.len() as i32 - 1) as usize;
            let delay = self.config.retry_delays[delay_index];
            let next_retry = Utc::now() + chrono::Duration::from_std(delay).unwrap();
            
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
        
        // Send via SMTP
        let mut sender = self.smtp_sender.lock().await;
        sender.send(
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
    
    /// Process a batch of emails
    async fn process_batch(&self) -> Result<()> {
        let emails = self.fetch_pending(self.config.batch_size as i64).await?;
        
        if emails.is_empty() {
            return Ok(());
        }
        
        info!(count = emails.len(), "Processing email batch");
        
        for email in &emails {
            match self.process_email(email).await {
                Ok(()) => {
                    self.mark_sent(&email.id).await?;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    let is_temporary = error_str.contains("timeout")
                        || error_str.contains("connection refused")
                        || error_str.contains("temporarily");
                    
                    self.mark_failed(&email.id, &error_str, is_temporary).await?;
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
