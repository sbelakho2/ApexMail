use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::dispatcher::LeadProfile;
use crate::types::{Campaign, CampaignStatus, SalesError};

// ---------------------------------------------------------------------------
// Campaign email dispatcher trait (SA-5)
// ---------------------------------------------------------------------------

/// A campaign dispatch target: recipient email plus the CAN-SPAM
/// unsubscribe link that MUST be appended to the outgoing message (SALES-02).
#[derive(Debug, Clone)]
pub struct DispatchRecipient {
    pub email: String,
    pub unsubscribe_link: String,
    /// Optional CRM lead profile used for template personalization
    /// (`{{first_name}}`, `{{company}}, …). Values are HTML-escaped by the
    /// renderer before interpolation.
    pub lead: Option<LeadProfile>,
}

impl DispatchRecipient {
    pub fn new(email: impl Into<String>, unsubscribe_link: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            unsubscribe_link: unsubscribe_link.into(),
            lead: None,
        }
    }
}

/// Recipient funnel counts for one campaign. Shared by the dry-run report
/// and the scheduler's completion gate (E): a campaign whose only remaining
/// recipients are `frequency_capped` must STAY active until the 7-day window
/// passes — completing it strands them forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecipientFunnel {
    pub total: i64,
    pub already_sent: i64,
    pub suppressed_local: i64,
    pub suppressed_platform: i64,
    /// Unsent and unsuppressed, but blocked by the per-recipient weekly
    /// frequency cap (fix I-2 CAN-SPAM) — becomes due when the cap window
    /// passes.
    pub frequency_capped: i64,
    /// Unsent, unsuppressed, within the cap — dispatchable right now.
    pub due: i64,
}

/// Maximum number of campaign emails a single recipient may receive within a
/// 7-day window (fix I-2 CAN-SPAM frequency cap).
pub const RECIPIENT_FREQUENCY_CAP_WEEKLY: i64 = 3;

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
    /// `recipients` is the full list of (email, unsubscribe_link) pairs —
    /// implementations MUST include the unsubscribe link in the rendered
    /// message footer (CAN-SPAM). Implementations should enqueue each
    /// recipient into the outbound email queue, using `template_id` for
    /// content rendering.
    ///
    /// Returns the number of emails successfully enqueued.
    fn dispatch(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        template_id: &str,
        recipients: &[DispatchRecipient],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, SalesError>> + Send>>;

    /// Generate a CAN-SPAM compliant unsubscribe link for a campaign recipient (SALES-02).
    ///
    /// Every commercial email sent through a campaign MUST include this link
    /// to provide recipients with a one-click unsubscribe mechanism.
    /// The link should point to a page that immediately processes the opt-out.
    ///
    /// Returns an absolute URL string such as
    /// `https://app.apexmail.ee/unsubscribe/{tenant_id}/{campaign_id}/{recipient_hash}`.
    fn unsubscribe_link(&self, tenant_id: &str, campaign_id: Uuid, recipient_email: &str)
        -> String;
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
        recipients: &[DispatchRecipient],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, SalesError>> + Send>>
    {
        let tenant_id = tenant_id.to_string();
        let template_id = template_id.to_string();
        let count = recipients.len();
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
        let _ = write!(
            hash_input,
            "{}:{}:{}",
            tenant_id, campaign_id, recipient_email
        );
        // Use SHA-256 to produce a deterministic, opaque hash of the recipient
        // details. The full hash is 64 hex chars; we take the first 16 for a
        // compact but sufficiently unique unsubscribe token (64-bit collision
        // space).
        let full_hash = apexmail_lib::hash_api_key(&hash_input);
        let hash_short = &full_hash[..16];
        format!(
            "https://sales.apexmail.ee/unsubscribe/{}/{}/{}",
            tenant_id, campaign_id, hash_short
        )
    }
}

/// Stats reconciliation SQL (see `reconcile_campaign_stats`): `sent` counts
/// worker 'sent' events joined via the send ledger's message_id (delivered
/// truth, audit F), falling back to the enqueue-time counter when no events
/// exist; `opened`/`clicked` fold the tracking-service message counters back
/// into the campaign columns.
const RECONCILE_CAMPAIGN_STATS_SQL: &str = r#"
            UPDATE sales_campaigns c SET
               sent = CASE WHEN EXISTS (
                   SELECT 1 FROM events e
                   JOIN sales_campaign_recipients r ON r.message_id::text = e.message_id
                   WHERE r.campaign_id = c.id AND e.event_type = 'sent'
               ) THEN (
                   SELECT COUNT(*) FROM events e
                   JOIN sales_campaign_recipients r ON r.message_id::text = e.message_id
                   WHERE r.campaign_id = c.id AND e.event_type = 'sent'
               ) ELSE c.sent END,
               opened = (
                 SELECT COUNT(*) FROM sales_campaign_recipients r
                 JOIN messages m ON m.id = r.message_id
                 WHERE r.campaign_id = c.id AND m.open_count > 0
               ),
               clicked = (
                 SELECT COUNT(*) FROM sales_campaign_recipients r
                 JOIN messages m ON m.id = r.message_id
                 WHERE r.campaign_id = c.id AND m.click_count > 0
               )
             WHERE c.id = $1
        "#;

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
    /// Maximum recipients dispatched per start/tick (bounded blast radius;
    /// the background scheduler loop continues beyond the first batch).
    dispatch_batch_size: usize,
}

impl CampaignManager {
    pub fn new(max_campaigns: usize, db: PgPool) -> Self {
        Self {
            db,
            max_campaigns,
            email_dispatcher: None,
            dispatch_batch_size: 100,
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

    /// Override the per-tick dispatch batch size (default 100).
    pub fn with_dispatch_batch_size(mut self, batch_size: usize) -> Self {
        self.dispatch_batch_size = batch_size.max(1);
        self
    }

    /// Fix I-1: does this manager have a real dispatcher wired? Production
    /// wiring failures must be loud — the start route refuses with 503 when
    /// this is false instead of returning 200 'active' while sending nothing.
    pub fn has_email_dispatcher(&self) -> bool {
        self.email_dispatcher.is_some()
    }

    /// The underlying pool (used by the scheduler to list active campaigns).
    pub fn db(&self) -> &PgPool {
        &self.db
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

        // Fix I-1 (manager level): without a dispatcher the campaign would
        // flip to 'active' and silently send nothing. Refuse BEFORE any
        // state transition; the route layer maps this to 503.
        if self.email_dispatcher.is_none() {
            return Err(SalesError::ServiceUnavailable(
                "email dispatcher not configured — campaign start refused (no emails would be sent)"
                    .into(),
            ));
        }

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
                // Fetch the FIRST dispatchable batch (bounded — the
                // background scheduler loop continues the campaign), attach
                // the CAN-SPAM unsubscribe footer link for each, and call
                // the email dispatcher (if configured). Dispatching happens
                // after the status commit; if it fails we surface the error
                // instead of pretending the start succeeded silently.
                if let Some(ref dispatcher) = self.email_dispatcher {
                    match self
                        .due_recipients(tenant_id, id, self.dispatch_batch_size as i64)
                        .await
                    {
                        Ok(recipients) if !recipients.is_empty() => {
                            match dispatcher
                                .dispatch(tenant_id, id, &template_id, &recipients)
                                .await
                            {
                                Ok(enqueued) => {
                                    tracing::info!(
                                        tenant_id = %tenant_id,
                                        campaign_id = %id,
                                        enqueued = enqueued,
                                        total_recipients = recipients.len(),
                                        "Campaign emails dispatched to outbound queue"
                                    );
                                    // Test/legacy dispatchers report only a
                                    // count; stamp the send ledger for them.
                                    // (The production dispatcher stamps each
                                    // recipient inside its own transaction, so
                                    // this UPDATE is a no-op there.)
                                    if enqueued == recipients.len() {
                                        let emails: Vec<String> =
                                            recipients.iter().map(|r| r.email.clone()).collect();
                                        if let Err(mark_err) =
                                            self.mark_recipients_sent(id, &emails).await
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
                                            requested = recipients.len(),
                                            "dispatcher enqueued fewer emails than requested — send ledger not advanced"
                                        );
                                    }
                                }
                                Err(SalesError::QuotaExhausted(_)) => {
                                    // Quota exhausted mid-batch: everything
                                    // dispatched so far is ledger-stamped; the
                                    // campaign PAUSES WITH AN ERROR STATE —
                                    // never a silent partial send.
                                    let reason = "email quota exhausted";
                                    if let Err(pause_err) = self.pause_with_error(id, reason).await
                                    {
                                        tracing::error!(
                                            error = %pause_err,
                                            campaign_id = %id,
                                            "failed to pause campaign after quota exhaustion"
                                        );
                                    }
                                    return Err(SalesError::ServiceUnavailable(
                                        "campaign paused: email quota exhausted".into(),
                                    ));
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        Ok(_) => {
                            tracing::warn!(
                                tenant_id = %tenant_id,
                                campaign_id = %id,
                                "Campaign started with zero dispatchable recipients — no emails dispatched"
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

    /// Fetch dispatchable ("due") recipients for a campaign: not yet sent,
    /// scoped to tenant, NOT suppressed (in the crate's `sales_unsubscribes`
    /// **or** the platform-wide `suppressions` table, exactly like the REST
    /// send path reads it), and within the per-recipient frequency cap.
    /// Bounded by `limit` (the dispatch batch size) and enriched with the
    /// CRM lead profile for template personalization.
    ///
    /// Send-ledger semantics: `sales_campaign_recipients.sent_at` records
    /// which recipients have already been sent to. Filtering on
    /// `sent_at IS NULL` means that pausing a campaign and re-starting it
    /// only dispatches the recipients that were never sent.
    ///
    /// Fix I-2 (CAN-SPAM): suppression + frequency cap run before any send.
    /// Each returned recipient carries the unsubscribe footer link that the
    /// dispatcher MUST append to the outgoing message.
    pub async fn due_recipients(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        limit: i64,
    ) -> Result<Vec<DispatchRecipient>, SalesError> {
        let dispatcher = self.email_dispatcher.clone().ok_or_else(|| {
            SalesError::ServiceUnavailable("email dispatcher not configured".into())
        })?;

        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT r.email, l.contact_name, l.company_name, l.title \
                 FROM sales_campaign_recipients r \
                 JOIN sales_campaigns c ON r.campaign_id = c.id \
                 LEFT JOIN sales_leads l \
                   ON l.tenant_id = c.tenant_id AND LOWER(l.contact_email) = LOWER(r.email) \
                 WHERE r.campaign_id = $1 AND c.tenant_id = $2 AND r.sent_at IS NULL \
                 AND NOT EXISTS (\
                     SELECT 1 FROM sales_unsubscribes u \
                     WHERE u.tenant_id = c.tenant_id AND u.email = r.email\
                 ) \
                 AND NOT EXISTS (\
                     SELECT 1 FROM suppressions s \
                     WHERE s.tenant_id = c.tenant_id AND LOWER(s.email) = LOWER(r.email)\
                 ) \
                 AND (\
                     SELECT COUNT(*) FROM sales_campaign_recipients r2 \
                     JOIN sales_campaigns c2 ON r2.campaign_id = c2.id \
                     WHERE r2.email = r.email AND c2.tenant_id = $2 \
                       AND r2.sent_at > NOW() - INTERVAL '7 days'\
                 ) < $3 \
                 ORDER BY r.email \
                 LIMIT $4",
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .bind(RECIPIENT_FREQUENCY_CAP_WEEKLY)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|(email, name, company, title)| {
                let link = dispatcher.unsubscribe_link(tenant_id, campaign_id, &email);
                DispatchRecipient {
                    email,
                    unsubscribe_link: link,
                    lead: Some(LeadProfile {
                        name: name.unwrap_or_default(),
                        company: company.unwrap_or_default(),
                        title: title.unwrap_or_default(),
                    }),
                }
            })
            .collect())
    }

    /// Pause an active campaign, recording WHY it was paused in
    /// `sales_campaigns.last_error` (e.g. "email quota exhausted"). Used by
    /// the dispatch paths so a stalled campaign is never a silent partial
    /// send — operators see the paused state plus the reason.
    pub async fn pause_with_error(
        &self,
        campaign_id: Uuid,
        reason: &str,
    ) -> Result<(), SalesError> {
        sqlx::query(
            "UPDATE sales_campaigns SET status = 'paused', last_error = $2 \
             WHERE id = $1 AND status = 'active'",
        )
        .bind(campaign_id)
        .bind(reason)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(())
    }

    /// Transition an active campaign to completed (no due recipients left).
    pub async fn complete_campaign(&self, campaign_id: Uuid) -> Result<(), SalesError> {
        sqlx::query(
            "UPDATE sales_campaigns SET status = 'completed', last_error = NULL \
             WHERE id = $1 AND status = 'active'",
        )
        .bind(campaign_id)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(())
    }

    /// Reconcile campaign engagement stats.
    ///
    /// * `opened` / `clicked` count the recipients whose dispatched message
    ///   has been opened/clicked. The per-message counters
    ///   (`messages.open_count` / `click_count`) are maintained by the
    ///   platform tracking service; this folds them back into the campaign
    ///   columns.
    /// * `sent` is reconciled to DELIVERED truth (audit F): the dispatcher
    ///   increments it at enqueue time (an intent count — a queued row can
    ///   still bounce or dead-letter), so this rewrite counts the worker's
    ///   `events` rows of type 'sent' joined through the send ledger's
    ///   `message_id`. When NO sent events exist yet (worker lag, or rows
    ///   enqueued but never processed), the enqueue-time counter is kept —
    ///   it remains the only available estimate rather than being zeroed.
    pub async fn reconcile_campaign_stats(&self, campaign_id: Uuid) -> Result<(), SalesError> {
        sqlx::query(RECONCILE_CAMPAIGN_STATS_SQL)
            .bind(campaign_id)
            .execute(&self.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(())
    }

    /// Recipient funnel counts for a campaign — one query, FILTERed
    /// aggregates (shared by [`Self::dry_run`] reporting and the scheduler's
    /// completion gate).
    pub async fn recipient_funnel_counts(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
    ) -> Result<RecipientFunnel, SalesError> {
        let funnel: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
                COUNT(*), \
                COUNT(*) FILTER (WHERE r.sent_at IS NOT NULL), \
                COUNT(*) FILTER (WHERE r.sent_at IS NULL AND EXISTS (\
                    SELECT 1 FROM sales_unsubscribes u \
                    WHERE u.tenant_id = c.tenant_id AND u.email = r.email)), \
                COUNT(*) FILTER (WHERE r.sent_at IS NULL AND NOT EXISTS (\
                    SELECT 1 FROM sales_unsubscribes u \
                    WHERE u.tenant_id = c.tenant_id AND u.email = r.email) AND EXISTS (\
                    SELECT 1 FROM suppressions s \
                    WHERE s.tenant_id = c.tenant_id AND LOWER(s.email) = LOWER(r.email))), \
                COUNT(*) FILTER (WHERE r.sent_at IS NULL AND NOT EXISTS (\
                    SELECT 1 FROM sales_unsubscribes u \
                    WHERE u.tenant_id = c.tenant_id AND u.email = r.email) AND NOT EXISTS (\
                    SELECT 1 FROM suppressions s \
                    WHERE s.tenant_id = c.tenant_id AND LOWER(s.email) = LOWER(r.email)) \
                    AND (\
                        SELECT COUNT(*) FROM sales_campaign_recipients r2 \
                        JOIN sales_campaigns c2 ON r2.campaign_id = c2.id \
                        WHERE r2.email = r.email AND c2.tenant_id = $2 \
                          AND r2.sent_at > NOW() - INTERVAL '7 days'\
                    ) >= $3), \
                COUNT(*) FILTER (WHERE r.sent_at IS NULL AND NOT EXISTS (\
                    SELECT 1 FROM sales_unsubscribes u \
                    WHERE u.tenant_id = c.tenant_id AND u.email = r.email) AND NOT EXISTS (\
                    SELECT 1 FROM suppressions s \
                    WHERE s.tenant_id = c.tenant_id AND LOWER(s.email) = LOWER(r.email)) \
                    AND (\
                        SELECT COUNT(*) FROM sales_campaign_recipients r2 \
                        JOIN sales_campaigns c2 ON r2.campaign_id = c2.id \
                        WHERE r2.email = r.email AND c2.tenant_id = $2 \
                          AND r2.sent_at > NOW() - INTERVAL '7 days'\
                    ) < $3) \
             FROM sales_campaign_recipients r \
             JOIN sales_campaigns c ON r.campaign_id = c.id \
             WHERE r.campaign_id = $1 AND c.tenant_id = $2",
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .bind(RECIPIENT_FREQUENCY_CAP_WEEKLY)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        let (total, already_sent, suppressed_local, suppressed_platform, capped, due) = funnel;
        Ok(RecipientFunnel {
            total,
            already_sent,
            suppressed_local,
            suppressed_platform,
            frequency_capped: capped,
            due,
        })
    }

    /// Dry-run a campaign: render templates and evaluate every dispatch
    /// filter (suppression, frequency cap, sender-domain readiness) WITHOUT
    /// enqueueing anything or stamping the send ledger. Operator safety net
    /// and test seam.
    ///
    /// `prod` is the production dispatcher when wired — it provides sender
    /// config and real unsubscribe links for the preview. Without it the
    /// report still contains the recipient funnel counts.
    pub async fn dry_run(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        sample_limit: usize,
        prod: Option<&crate::dispatcher::ProductionCampaignDispatcher>,
    ) -> Result<serde_json::Value, SalesError> {
        let row: Option<CampaignRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        let campaign = row
            .and_then(|r| r.into_campaign().ok())
            .ok_or(SalesError::CampaignNotFound(campaign_id))?;

        // Recipient funnel counts (shared query — see
        // `recipient_funnel_counts`, also used by the scheduler's completion
        // gate).
        let funnel = self.recipient_funnel_counts(tenant_id, campaign_id).await?;
        let RecipientFunnel {
            total,
            already_sent,
            suppressed_local,
            suppressed_platform,
            frequency_capped: capped,
            due,
        } = funnel;

        let mut warnings: Vec<String> = Vec::new();

        // Sender readiness + template resolution + rendered previews when
        // the production dispatcher is wired.
        let sender = match prod {
            Some(p) => {
                let domain_ok = crate::dispatcher::sender_domain_ready(
                    &self.db,
                    tenant_id,
                    &p.config().from_email,
                )
                .await
                .unwrap_or(false);
                if !domain_ok {
                    warnings.push(format!(
                        "sender domain of '{}' is not verified/DKIM-ready for this tenant — start would refuse",
                        p.config().from_email
                    ));
                }
                Some(serde_json::json!({
                    "from": p.config().from_email,
                    "from_name": p.config().from_name,
                    "domain_verified": domain_ok,
                }))
            }
            None => {
                warnings.push(
                    "production dispatcher not configured — sender readiness and message previews skipped"
                        .into(),
                );
                None
            }
        };

        let template =
            match crate::dispatcher::fetch_template(&self.db, tenant_id, &campaign.template_id)
                .await
            {
                Ok(t) => Some(serde_json::json!({
                    "id": campaign.template_id,
                    "subject": t.subject,
                    "has_html": t.html_body.is_some(),
                    "has_text": t.text_body.is_some(),
                })),
                Err(e) => {
                    warnings.push(format!("template not renderable: {e}"));
                    None
                }
            };

        // Render previews for up to `sample_limit` due recipients.
        let mut preview = Vec::new();
        if let Some(p) = prod {
            if let Ok(template_content) =
                crate::dispatcher::fetch_template(&self.db, tenant_id, &campaign.template_id).await
            {
                let sample = self
                    .due_recipients(tenant_id, campaign_id, sample_limit as i64)
                    .await
                    .unwrap_or_default();
                for recipient in sample {
                    let rendered = crate::dispatcher::render_for_recipient(
                        &template_content,
                        &recipient,
                        &p.config().from_name,
                    )?;
                    preview.push(serde_json::json!({
                        "email": recipient.email,
                        "subject": rendered.subject,
                        "unsubscribe_link": recipient.unsubscribe_link,
                    }));
                }
            }
        }

        Ok(serde_json::json!({
            "campaign_id": campaign_id.to_string(),
            "status": campaign.status.to_string(),
            "dry_run": true,
            "sender": sender,
            "template": template,
            "recipients": {
                "total": total,
                "already_sent": already_sent,
                "suppressed_local": suppressed_local,
                "suppressed_platform": suppressed_platform,
                "frequency_capped": capped,
                "due": due,
            },
            "preview": preview,
            "warnings": warnings,
        }))
    }

    /// Record an unsubscribe (suppression) for a tenant (fix I-2).
    /// Suppressed recipients are excluded from every future campaign send.
    pub async fn suppress_recipient(&self, tenant_id: &str, email: &str) -> Result<(), SalesError> {
        sqlx::query(
            "INSERT INTO sales_unsubscribes (tenant_id, email, created_at) \
             VALUES ($1, $2, NOW()) ON CONFLICT (tenant_id, email) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(email)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(())
    }

    /// Is a recipient currently suppressed for this tenant (fix I-2)?
    pub async fn is_recipient_suppressed(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<bool, SalesError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1 AND email = $2",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(count > 0)
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
        assert!(mgr
            .list_campaigns("tenant-b", 100, 0)
            .await
            .unwrap()
            .is_empty());
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
        assert!(!is_valid_recipient_email(&format!(
            "{long_local}@example.com"
        )));
    }

    #[tokio::test]
    async fn test_noop_dispatcher_fails_explicitly() {
        // The noop dispatcher must fail loudly instead of reporting Ok(0),
        // which previously made `start_campaign` look successful while no
        // email was ever dispatched.
        let dispatcher = NoopCampaignDispatcher;
        let recipients = [DispatchRecipient {
            email: "a@x.com".into(),
            unsubscribe_link: dispatcher.unsubscribe_link("tenant-a", Uuid::new_v4(), "a@x.com"),
            lead: None,
        }];
        let result = dispatcher
            .dispatch("tenant-a", Uuid::new_v4(), "tmpl_1", &recipients)
            .await;
        assert!(result.is_err());
    }

    // ── F: sent-counter honesty in reconcile_campaign_stats ─────────────

    /// The reconciliation must derive `sent` from the worker's 'sent' events
    /// joined via the ledger message_id, and fall back to the stored
    /// (enqueue-time) counter when no events exist — never blanket-zero it.
    #[test]
    fn reconcile_sql_counts_sent_events_with_enqueue_fallback() {
        let sql = RECONCILE_CAMPAIGN_STATS_SQL;
        // Delivered-truth join through the send ledger's message_id.
        assert!(
            sql.contains("JOIN sales_campaign_recipients r ON r.message_id::text = e.message_id"),
            "sent must be counted from events joined via message_id"
        );
        assert!(
            sql.contains("e.event_type = 'sent'"),
            "only worker 'sent' events count"
        );
        // Fallback path: absent events keep the enqueue-time counter.
        assert!(
            sql.contains("ELSE c.sent END"),
            "no events => keep the enqueue-time count"
        );
        // Opens/clicks reconciliation is preserved.
        assert!(sql.contains("m.open_count > 0"));
        assert!(sql.contains("m.click_count > 0"));
    }

    /// Integration (local Postgres): both reconciliation paths —
    /// (1) events present → `sent` is rewritten to the events count;
    /// (2) events absent → `sent` keeps the enqueue-time count.
    #[ignore = "requires local PostgreSQL with the sales-autopilot schema"]
    #[tokio::test]
    async fn reconcile_sent_counter_follows_events_or_falls_back() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
                "postgres://apexmail:apexmail@localhost:5432/apexmail".to_string()
            }))
            .await
            .unwrap();
        crate::routes::initialize_schema(&db).await.unwrap();

        let manager = CampaignManager::new(10, db.clone());
        let campaign = manager
            .create_campaign(
                "stats-f-test".into(),
                "stats".into(),
                "t".into(),
                "all".into(),
            )
            .await
            .unwrap();
        manager
            .add_recipients(
                "stats-f-test",
                campaign.id,
                vec!["a@x.com".into(), "b@x.com".into(), "c@x.com".into()],
            )
            .await
            .unwrap();
        // Simulate three enqueues (dispatcher increments at enqueue time).
        sqlx::query("UPDATE sales_campaigns SET sent = 3 WHERE id = $1")
            .bind(campaign.id)
            .execute(&db)
            .await
            .unwrap();

        // Path 2 first: NO events yet — reconcile keeps the enqueue count.
        manager.reconcile_campaign_stats(campaign.id).await.unwrap();
        let sent: i64 = sqlx::query_scalar("SELECT sent FROM sales_campaigns WHERE id = $1")
            .bind(campaign.id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(sent, 3, "no events => enqueue count is kept, not zeroed");

        // Simulate the worker having recorded only TWO 'sent' events (the
        // third row is still queued / bounced): delivered truth is 2.
        let message_ids: Vec<Uuid> = sqlx::query_scalar(
            "UPDATE sales_campaign_recipients \
                 SET sent_at = NOW(), message_id = gen_random_uuid() \
                 WHERE campaign_id = $1 AND email IN ('a@x.com', 'b@x.com') RETURNING message_id",
        )
        .bind(campaign.id)
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(message_ids.len(), 2);
        for mid in &message_ids {
            sqlx::query(
                "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) \
                 VALUES ($1, $2, $3, 'sent', 'x', NOW())",
            )
            .bind(format!("evt_{}", uuid::Uuid::new_v4()))
            .bind("stats-f-test")
            .bind(mid.to_string())
            .execute(&db)
            .await
            .unwrap();
        }

        // Path 1: events exist — sent is rewritten to the events count.
        manager.reconcile_campaign_stats(campaign.id).await.unwrap();
        let sent: i64 = sqlx::query_scalar("SELECT sent FROM sales_campaigns WHERE id = $1")
            .bind(campaign.id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(sent, 2, "sent must reflect delivered truth from events");

        sqlx::query("DELETE FROM sales_campaigns WHERE id = $1")
            .bind(campaign.id)
            .execute(&db)
            .await
            .unwrap();
    }
}
