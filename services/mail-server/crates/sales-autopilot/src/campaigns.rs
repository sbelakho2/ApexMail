use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::types::{Campaign, CampaignStatus, SalesError};

// ---------------------------------------------------------------------------
// Campaign email dispatcher trait (SA-5)
// ---------------------------------------------------------------------------

/// Abstraction for dispatching campaign emails to the outbound queue.
///
/// # Security (SA-5)
///
/// **Root cause**: `start_campaign` merely set a status flag to `'active'`
/// without actually sending emails through the outbound queue. Campaign
/// recipients were stored in the database but never delivered.
///
/// **Fix**: Added the `CampaignEmailDispatcher` trait as an injectable
/// dependency on `CampaignManager`. When a campaign transitions to Active,
/// `start_campaign` calls `dispatch()` with the campaign details so the
/// caller can enqueue outbound emails. This keeps the sales-autopilot crate
/// decoupled from the delivery worker (no direct dependency).
pub trait CampaignEmailDispatcher: Send + Sync + std::fmt::Debug {
    /// Dispatch emails for a campaign that has just been started.
    ///
    /// `tenant_id` and `campaign_id` identify the campaign.
    /// `recipient_emails` is the full list of campaign recipients.
    /// Implementations should enqueue each recipient into the outbound
    /// email queue, using `template_id` for content rendering.
    ///
    /// Returns the number of emails successfully enqueued.
    fn dispatch(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        template_id: &str,
        recipient_emails: &[String],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, SalesError>> + Send>>;

    /// Generate a CAN-SPAM compliant unsubscribe link for a campaign recipient (SALES-02).
    ///
    /// Every commercial email sent through a campaign MUST include this link
    /// to provide recipients with a one-click unsubscribe mechanism.
    /// The link should point to a page that immediately processes the opt-out.
    ///
    /// Returns an absolute URL string such as
    /// `https://app.apexmail.ee/unsubscribe/{tenant_id}/{campaign_id}/{recipient_hash}`.
    fn unsubscribe_link(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        recipient_email: &str,
    ) -> String;
}

/// A no-op dispatcher used as the default. Logs that campaign emails
/// were not dispatched.
#[derive(Debug, Clone)]
pub struct NoopCampaignDispatcher;

impl CampaignEmailDispatcher for NoopCampaignDispatcher {
    fn dispatch(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        template_id: &str,
        recipient_emails: &[String],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, SalesError>> + Send>>
    {
        let tenant_id = tenant_id.to_string();
        let template_id = template_id.to_string();
        let count = recipient_emails.len();
        Box::pin(async move {
            tracing::warn!(
                tenant_id = %tenant_id,
                campaign_id = %campaign_id,
                template_id = %template_id,
                recipient_count = count,
                "NoopCampaignDispatcher: no email dispatcher configured"
            );
            // Fail explicitly instead of returning Ok(0): a silent zero
            // made `start_campaign` report success while nothing was sent.
            Err(SalesError::Internal(anyhow::anyhow!(
                "no email dispatcher configured"
            )))
        })
    }

    fn unsubscribe_link(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        recipient_email: &str,
    ) -> String {
        use std::fmt::Write;
        let mut hash_input = String::new();
        let _ = write!(hash_input, "{}:{}:{}", tenant_id, campaign_id, recipient_email);
        // Use SHA-256 to produce a deterministic, opaque hash of the recipient
        // details. The full hash is 64 hex chars; we take the first 16 for a
        // compact but sufficiently unique unsubscribe token (64-bit collision
        // space).
        let full_hash = apexmail_lib::hash_api_key(&hash_input);
        let hash_short = &full_hash[..16];
        format!("https://sales.apexmail.ee/unsubscribe/{}/{}/{}", tenant_id, campaign_id, hash_short)
    }
}

/// PostgreSQL-backed campaign manager.
/// Campaigns and recipients are persisted across restarts.
#[derive(Debug, Clone)]
pub struct CampaignManager {
    db: PgPool,
    max_campaigns: usize,
    /// Optional outbound email dispatcher (SA-5).
    /// When `Some`, campaign start will enqueue emails for delivery.
    /// When `None` (default), a warning is logged and no emails are sent.
    email_dispatcher: Option<std::sync::Arc<dyn CampaignEmailDispatcher>>,
}

impl CampaignManager {
    pub fn new(max_campaigns: usize, db: PgPool) -> Self {
        Self {
            db,
            max_campaigns,
            email_dispatcher: None,
        }
    }

    /// Attach an email dispatcher for outbound campaign email delivery (SA-5).
    pub fn with_email_dispatcher(
        mut self,
        dispatcher: std::sync::Arc<dyn CampaignEmailDispatcher>,
    ) -> Self {
        self.email_dispatcher = Some(dispatcher);
        self
    }

    /// Create a campaign in Draft status.
    pub async fn create_campaign(
        &self,
        tenant_id: String,
        name: String,
        template_id: String,
        audience: String,
    ) -> Result<Campaign, SalesError> {
        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_campaigns WHERE tenant_id = $1 AND status = 'active'",
        )
        .bind(&tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if active_count >= self.max_campaigns as i64 {
            return Err(SalesError::MaxCampaignsReached(self.max_campaigns));
        }

        let campaign = Campaign {
            id: Uuid::new_v4(),
            tenant_id,
            name,
            template_id,
            audience,
            status: CampaignStatus::Draft,
            sent: 0,
            opened: 0,
            clicked: 0,
            created_at: Utc::now(),
        };

        sqlx::query(
            "INSERT INTO sales_campaigns (id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(campaign.id)
        .bind(&campaign.tenant_id)
        .bind(&campaign.name)
        .bind(&campaign.template_id)
        .bind(&campaign.audience)
        .bind(campaign.status.to_string())
        .bind(campaign.sent as i64)
        .bind(campaign.opened as i64)
        .bind(campaign.clicked as i64)
        .bind(campaign.created_at)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(campaign)
    }

    /// List all campaigns for a tenant.
    ///
    /// Returns `Err` on database failure — previously errors were logged and
    /// silently converted into an empty list, which callers could not
    /// distinguish from "no campaigns".
    pub async fn list_campaigns(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Campaign>, SalesError> {
        let rows = sqlx::query_as::<_, CampaignRow>(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at FROM sales_campaigns WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|r| r.into_campaign())
            .collect::<Result<Vec<_>, _>>()
    }

    /// Transition a draft/paused campaign to Active.
    ///
    /// # Security (SA-13)
    ///
    /// **Root cause**: The previous implementation used a SELECT-then-UPDATE
    /// pattern where the UPDATE SQL omitted `tenant_id`. This created a TOCTOU
    /// (time-of-check-time-of-use) race window: between the SELECT verifying
    /// tenant ownership and the UPDATE, another concurrent request could modify
    /// the campaign state, potentially allowing cross-tenant state manipulation.
    ///
    /// **Fix**: Replaced the SELECT-then-UPDATE with a single atomic conditional
    /// UPDATE that includes:
    ///   - `AND tenant_id = $2` — prevents cross-tenant manipulation
    ///   - `AND status = $3` — atomic state transition (fails if status changed
    ///     between read and write, eliminating the race window entirely)
    ///
    ///   The UPDATE `RETURNING *` is used so the caller receives the confirmed
    ///   new state without a follow-up SELECT.
    pub async fn start_campaign(&self, tenant_id: &str, id: Uuid) -> Result<Campaign, SalesError> {
        let row: Option<CampaignRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let campaign = row
            .and_then(|r| r.into_campaign().ok())
            .ok_or(SalesError::CampaignNotFound(id))?;

        let template_id = campaign.template_id.clone();

        match campaign.status {
            CampaignStatus::Draft | CampaignStatus::Paused => {
                // Enforce the max-active-campaigns limit at start time as well.
                //
                // `create_campaign` only counts ACTIVE campaigns, so a tenant
                // can create unlimited drafts and then start them all — the
                // create-time check alone is bypassable. The count and the
                // status UPDATE below run inside a single transaction so that
                // concurrent starts cannot both pass the count check (TOCTOU).
                let mut tx = self
                    .db
                    .begin()
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;

                let active_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM sales_campaigns WHERE tenant_id = $1 AND status = 'active'",
                )
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;

                if active_count >= self.max_campaigns as i64 {
                    // Nothing written in this transaction yet — dropping it
                    // rolls back (a no-op).
                    return Err(SalesError::MaxCampaignsReached(self.max_campaigns));
                }

                // Atomic conditional UPDATE: tenant filter + expected status
                // eliminate the TOCTOU race window (SA-13).
                let expected_status = campaign.status.to_string();
                let updated_row: Option<CampaignRow> = tokio::time::timeout(
                    Duration::from_secs(30),
                    sqlx::query_as(
                        "UPDATE sales_campaigns SET status = 'active' WHERE id = $1 AND tenant_id = $2 AND status = $3 RETURNING id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at",
                    )
                    .bind(id)
                    .bind(tenant_id)
                    .bind(&expected_status)
                    .fetch_optional(&mut *tx),
                )
                .await
                .map_err(|_| SalesError::Database("campaign start query timed out".into()))?
                .map_err(|e| SalesError::Database(e.to_string()))?;

                let updated = match updated_row.and_then(|r| r.into_campaign().ok()) {
                    Some(c) => c,
                    None => {
                        return Err(SalesError::InvalidInput(
                            "campaign status changed concurrently; retry".into(),
                        ))
                    }
                };

                tx.commit()
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;

                // SA-5: Dispatch campaign emails to the outbound queue.
                // Fetch the recipients that have NOT been sent to yet (see
                // `get_recipients`) and call the email dispatcher (if
                // configured). Dispatching happens after the status commit;
                // if it fails we surface the error instead of pretending the
                // start succeeded silently.
                if let Some(ref dispatcher) = self.email_dispatcher {
                    match self.get_recipients(tenant_id, id).await {
                        Ok(emails) if !emails.is_empty() => {
                            let enqueued = dispatcher
                                .dispatch(tenant_id, id, &template_id, &emails)
                                .await?;
                            tracing::info!(
                                tenant_id = %tenant_id,
                                campaign_id = %id,
                                enqueued = enqueued,
                                total_recipients = emails.len(),
                                "Campaign emails dispatched to outbound queue"
                            );
                            // Advance the send ledger only when the dispatcher
                            // accepted every recipient; partial enqueues are
                            // ambiguous (the dispatcher reports only a count),
                            // so we retry the full batch on the next start
                            // rather than risk skipping recipients.
                            if enqueued == emails.len() {
                                if let Err(mark_err) = self.mark_recipients_sent(id, &emails).await
                                {
                                    tracing::warn!(
                                        error = %mark_err,
                                        tenant_id = %tenant_id,
                                        campaign_id = %id,
                                        "failed to record sent_at send ledger — dispatched recipients may be re-dispatched on the next start"
                                    );
                                }
                            } else {
                                tracing::warn!(
                                    tenant_id = %tenant_id,
                                    campaign_id = %id,
                                    enqueued = enqueued,
                                    requested = emails.len(),
                                    "dispatcher enqueued fewer emails than requested — send ledger not advanced"
                                );
                            }
                        }
                        Ok(_) => {
                            tracing::warn!(
                                tenant_id = %tenant_id,
                                campaign_id = %id,
                                "Campaign started with zero unsent recipients — no emails dispatched"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                tenant_id = %tenant_id,
                                campaign_id = %id,
                                "Failed to fetch campaign recipients for email dispatch"
                            );
                            // The status transition above is already committed;
                            // still surface the failure instead of returning Ok.
                            return Err(e);
                        }
                    }
                } else {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        campaign_id = %id,
                        template_id = %template_id,
                        "No CampaignEmailDispatcher configured — campaign emails NOT dispatched. "
                    );
                }

                Ok(updated)
            }
            _ => Err(SalesError::InvalidInput(format!(
                "cannot start campaign in status {}",
                campaign.status
            ))),
        }
    }

    /// Fetch the recipient emails for a campaign that have **not yet been
    /// dispatched**, scoped to tenant.
    ///
    /// Send-ledger semantics: `sales_campaign_recipients.sent_at` (added in
    /// `initialize_schema`) records which recipients have already been sent
    /// to. Filtering on `sent_at IS NULL` means that pausing a campaign and
    /// re-starting it only dispatches the recipients that were never sent —
    /// previously every (re-)start re-dispatched the entire list, spamming
    /// everyone on each pause/start cycle. `mark_recipients_sent` stamps the
    /// ledger after a successful dispatch.
    async fn get_recipients(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
    ) -> Result<Vec<String>, SalesError> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT r.email FROM sales_campaign_recipients r \
             JOIN sales_campaigns c ON r.campaign_id = c.id \
             WHERE r.campaign_id = $1 AND c.tenant_id = $2 AND r.sent_at IS NULL",
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|(email,)| email).collect())
    }

    /// Stamp the send ledger: mark the given recipients as dispatched for a
    /// campaign (see `get_recipients` for why this matters).
    async fn mark_recipients_sent(
        &self,
        campaign_id: Uuid,
        emails: &[String],
    ) -> Result<u64, SalesError> {
        let result = sqlx::query(
            "UPDATE sales_campaign_recipients SET sent_at = NOW() WHERE campaign_id = $1 AND email = ANY($2) AND sent_at IS NULL",
        )
        .bind(campaign_id)
        .bind(emails)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Pause an active campaign.
    ///
    /// # Security (SA-13)
    ///
    /// Same TOCTOU fix as `start_campaign`: atomic conditional UPDATE with
    /// `tenant_id` filter and `AND status = 'active'` prevents cross-tenant
    /// manipulation and race-condition state corruption.
    pub async fn pause_campaign(&self, tenant_id: &str, id: Uuid) -> Result<Campaign, SalesError> {
        let row: Option<CampaignRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let campaign = row
            .and_then(|r| r.into_campaign().ok())
            .ok_or(SalesError::CampaignNotFound(id))?;

        if campaign.status != CampaignStatus::Active {
            return Err(SalesError::InvalidInput("campaign is not active".into()));
        }

        // Atomic conditional UPDATE: tenant filter + expected status
        // eliminate the TOCTOU race window (SA-13).
        let updated_row: Option<CampaignRow> = tokio::time::timeout(
            Duration::from_secs(30),
            sqlx::query_as(
                "UPDATE sales_campaigns SET status = 'paused' WHERE id = $1 AND tenant_id = $2 AND status = 'active' RETURNING id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at",
            )
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(&self.db),
        )
        .await
        .map_err(|_| SalesError::Database("campaign pause query timed out".into()))?
        .map_err(|e| SalesError::Database(e.to_string()))?;

        match updated_row.and_then(|r| r.into_campaign().ok()) {
            Some(updated) => Ok(updated),
            None => Err(SalesError::InvalidInput(
                "campaign status changed concurrently or is not active; retry".into(),
            )),
        }
    }

    /// Return stats for a campaign (sent / opened / clicked / recipients).
    /// Requires `tenant_id` to enforce tenant isolation — returns
    /// `CampaignNotFound` if the campaign does not belong to this tenant.
    pub async fn get_stats(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<serde_json::Value, SalesError> {
        let row: Option<CampaignRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let c = row
            .and_then(|r| r.into_campaign().ok())
            .ok_or(SalesError::CampaignNotFound(id))?;

        let recipient_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_campaign_recipients r \
             JOIN sales_campaigns c ON r.campaign_id = c.id \
             WHERE r.campaign_id = $1 AND c.tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(serde_json::json!({
            "campaign_id": c.id,
            "tenant_id": c.tenant_id,
            "status": c.status,
            "sent": c.sent,
            "opened": c.opened,
            "clicked": c.clicked,
            "recipients": recipient_count,
        }))
    }

    /// Add recipient emails to a campaign. Deduplicates against existing entries.
    pub async fn add_recipients(
        &self,
        tenant_id: &str,
        id: Uuid,
        emails: Vec<String>,
    ) -> Result<usize, SalesError> {
        // Verify campaign exists and belongs to tenant
        let exists: bool = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
            > 0;

        if !exists {
            return Err(SalesError::CampaignNotFound(id));
        }

        let mut added = 0usize;
        for email in emails {
            let normalized = email.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                continue;
            }
            // Reject syntactically invalid addresses instead of silently
            // persisting garbage that would later bounce.
            if !is_valid_recipient_email(&normalized) {
                return Err(SalesError::InvalidInput(format!(
                    "invalid recipient email: {email}"
                )));
            }
            let result = sqlx::query(
                "INSERT INTO sales_campaign_recipients (campaign_id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(&normalized)
            .execute(&self.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

            if result.rows_affected() > 0 {
                added += 1;
            }
        }

        Ok(added)
    }
}

/// Basic syntactic validation for recipient email addresses.
///
/// Checks: total length < 320, no whitespace, exactly one `@`, a non-empty
/// local part, and a domain part containing at least one `.` that is not at
/// the start or end. Deliberately minimal — full RFC 5321/5322 validation is
/// out of scope for this service.
fn is_valid_recipient_email(email: &str) -> bool {
    if email.len() >= 320 || email.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

// ---------------------------------------------------------------------------
// Internal row type for sqlx mapping
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct CampaignRow {
    id: Uuid,
    tenant_id: String,
    name: String,
    template_id: String,
    audience: String,
    status: String,
    sent: i64,
    opened: i64,
    clicked: i64,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl CampaignRow {
    fn into_campaign(self) -> Result<Campaign, SalesError> {
        let status = match self.status.as_str() {
            "draft" => CampaignStatus::Draft,
            "active" => CampaignStatus::Active,
            "paused" => CampaignStatus::Paused,
            "completed" => CampaignStatus::Completed,
            other => {
                return Err(SalesError::Internal(anyhow::anyhow!(
                    "unknown campaign status: {other}"
                )));
            }
        };
        Ok(Campaign {
            id: self.id,
            tenant_id: self.tenant_id,
            name: self.name,
            template_id: self.template_id,
            audience: self.audience,
            status,
            sent: self.sent as u64,
            opened: self.opened as u64,
            clicked: self.clicked as u64,
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an in-memory SQLite-like manager backed by a
    /// `connect_lazy` pool. Tests using this will not persist data
    /// between test functions.
    async fn make_mgr() -> CampaignManager {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        CampaignManager::new(10, db)
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_create_and_list() {
        let mgr = make_mgr().await;
        let c = mgr
            .create_campaign(
                "tenant-a".into(),
                "Welcome".into(),
                "tmpl_1".into(),
                "all_leads".into(),
            )
            .await
            .unwrap();
        assert_eq!(c.status, CampaignStatus::Draft);
        let list = mgr.list_campaigns("tenant-a", 100, 0).await.unwrap();
        assert!(!list.is_empty());
        assert!(mgr.list_campaigns("tenant-b", 100, 0).await.unwrap().is_empty());
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_start_pause_lifecycle() {
        let mgr = make_mgr().await;
        let c = mgr
            .create_campaign(
                "tenant-a".into(),
                "Drip".into(),
                "tmpl_2".into(),
                "new_leads".into(),
            )
            .await
            .unwrap();
        let started = mgr.start_campaign("tenant-a", c.id).await.unwrap();
        assert_eq!(started.status, CampaignStatus::Active);

        let paused = mgr.pause_campaign("tenant-a", c.id).await.unwrap();
        assert_eq!(paused.status, CampaignStatus::Paused);

        // re-start after pause
        let restarted = mgr.start_campaign("tenant-a", c.id).await.unwrap();
        assert_eq!(restarted.status, CampaignStatus::Active);
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_max_campaigns_enforced() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let mgr = CampaignManager::new(1, db);
        let c = mgr
            .create_campaign("tenant-a".into(), "C1".into(), "t".into(), "a".into())
            .await
            .unwrap();
        mgr.start_campaign("tenant-a", c.id).await.unwrap();

        // second active campaign should be rejected
        let c2 = mgr
            .create_campaign("tenant-a".into(), "C2".into(), "t".into(), "a".into())
            .await;
        assert!(c2.is_err());
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    ///
    /// The create-time limit counts only ACTIVE campaigns, so a tenant can
    /// stockpile drafts. The limit must therefore be re-checked when the
    /// campaign is started.
    #[ignore]
    #[tokio::test]
    async fn test_max_campaigns_enforced_at_start() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let mgr = CampaignManager::new(1, db);

        // Two drafts both pass the create-time check (zero active campaigns).
        let c1 = mgr
            .create_campaign("tenant-x".into(), "C1".into(), "t".into(), "a".into())
            .await
            .unwrap();
        let c2 = mgr
            .create_campaign("tenant-x".into(), "C2".into(), "t".into(), "a".into())
            .await
            .unwrap();

        mgr.start_campaign("tenant-x", c1.id).await.unwrap();

        // Starting the second draft must be rejected by the start-time check.
        assert!(matches!(
            mgr.start_campaign("tenant-x", c2.id).await,
            Err(SalesError::MaxCampaignsReached(1))
        ));
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_recipients_and_stats() {
        let mgr = make_mgr().await;
        let c = mgr
            .create_campaign(
                "tenant-a".into(),
                "Outreach".into(),
                "tmpl".into(),
                "saas".into(),
            )
            .await
            .unwrap();
        let added = mgr
            .add_recipients("tenant-a", c.id, vec!["a@x.com".into(), "b@x.com".into()])
            .await
            .unwrap();
        assert_eq!(added, 2);

        let stats = mgr.get_stats("tenant-a", c.id).await.unwrap();
        assert_eq!(stats["recipients"], 2);
        assert_eq!(stats["sent"], 0);
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_campaign_operations_are_tenant_scoped() {
        let mgr = make_mgr().await;
        let campaign = mgr
            .create_campaign(
                "tenant-a".into(),
                "Scoped".into(),
                "tmpl".into(),
                "all".into(),
            )
            .await
            .unwrap();

        assert!(matches!(
            mgr.start_campaign("tenant-b", campaign.id).await,
            Err(SalesError::CampaignNotFound(id)) if id == campaign.id
        ));
        assert!(matches!(
            mgr.add_recipients("tenant-b", campaign.id, vec!["user@example.com".into()]).await,
            Err(SalesError::CampaignNotFound(id)) if id == campaign.id
        ));
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_add_recipients_deduplicates_addresses() {
        let mgr = make_mgr().await;
        let campaign = mgr
            .create_campaign(
                "tenant-a".into(),
                "Scoped".into(),
                "tmpl".into(),
                "all".into(),
            )
            .await
            .unwrap();

        let added = mgr
            .add_recipients(
                "tenant-a",
                campaign.id,
                vec![
                    "alice@example.com".into(),
                    " ALICE@example.com ".into(),
                    "bob@example.com".into(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(added, 2);
        let stats = mgr.get_stats("tenant-a", campaign.id).await.unwrap();
        assert_eq!(stats["recipients"], 2);
    }

    #[test]
    fn test_recipient_email_validation() {
        assert!(is_valid_recipient_email("alice@example.com"));
        assert!(is_valid_recipient_email("a+b_tag@sub.domain.co"));
        // missing @ / missing dot in domain / empty parts
        assert!(!is_valid_recipient_email("no-at-sign.com"));
        assert!(!is_valid_recipient_email("@example.com"));
        assert!(!is_valid_recipient_email("alice@"));
        assert!(!is_valid_recipient_email("alice@example"));
        assert!(!is_valid_recipient_email("alice@.example.com"));
        assert!(!is_valid_recipient_email("alice@example.com."));
        // multiple @ and whitespace are rejected
        assert!(!is_valid_recipient_email("a@b@example.com"));
        assert!(!is_valid_recipient_email("a lice@example.com"));
        // total length must stay under 320
        let long_local = "x".repeat(315);
        assert!(!is_valid_recipient_email(&format!("{long_local}@example.com")));
    }

    #[tokio::test]
    async fn test_noop_dispatcher_fails_explicitly() {
        // The noop dispatcher must fail loudly instead of reporting Ok(0),
        // which previously made `start_campaign` look successful while no
        // email was ever dispatched.
        let dispatcher = NoopCampaignDispatcher;
        let result = dispatcher
            .dispatch("tenant-a", Uuid::new_v4(), "tmpl_1", &["a@x.com".into()])
            .await;
        assert!(result.is_err());
    }
}
