//! Legacy campaign compatibility planner (the CP-facing `sales_campaigns`
//! model) — and NOTHING else.
//!
//! `sales_campaigns` / `sales_campaign_recipients` are kept as a read
//! compatibility ledger for the control plane. They are **not** a send
//! engine: `start_campaign` adapts every recipient into the canonical model
//! and enrolls it through [`crate::enrollments::start_outreach`], so every
//! campaign email is executed by the durable action worker and passes the
//! Decision Packet, the legal gate, the sender-health gate and the action
//! fence. There is no `CampaignEmailDispatcher`, no `dispatch_batch` and no
//! direct enqueue into the platform queue from this module.

use chrono::Utc;
use sqlx::PgPool;
use std::collections::HashSet;
use std::time::Duration;
use uuid::Uuid;

use crate::actions::ActionQueue;
use crate::dispatcher::{sign_unsubscribe_token_default_ttl, LeadProfile};
use crate::enrollments::{self, StartOutreachRequest, StartOutreachResponse};
use crate::types::{Campaign, CampaignStatus, SalesError};

// ---------------------------------------------------------------------------
// Shared value types
// ---------------------------------------------------------------------------

/// A render target for the sequence worker / dry-run preview: recipient email
/// plus the CAN-SPAM unsubscribe link that MUST be appended to the outgoing
/// message (SALES-02). This struct is not a dispatch entry point.
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

/// Recipient funnel counts for one campaign, used by the dry-run report:
/// `frequency_capped` recipients are not currently due (7-day per-recipient
/// window, fix I-2 CAN-SPAM).
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
    /// Unsent, unsuppressed, within the cap — due right now.
    pub due: i64,
}

/// Maximum number of campaign emails a single recipient may receive within a
/// 7-day window (fix I-2 CAN-SPAM frequency cap). Retained for the dry-run
/// funnel report: the canonical send path enforces its own frequency budget.
pub const RECIPIENT_FREQUENCY_CAP_WEEKLY: i64 = 3;

/// Verification recorded for a contact point materialized from a legacy
/// campaign recipient.
///
/// A legacy `sales_campaign_recipients` row carries no verification
/// provenance (no provider, no check, no timestamp), so the point must never
/// claim `valid`: it is stored as `unknown` and the canonical legal /
/// verification gates downstream decide whether it may be contacted.
pub const LEGACY_RECIPIENT_VERIFICATION: &str = "unknown";

/// Confidence recorded for a contact point materialized from a legacy
/// campaign recipient. Deliberately low and documented: the address was
/// imported from a campaign audience, not verified.
pub const LEGACY_RECIPIENT_CONFIDENCE: f64 = 0.1;

/// `sales_contact_points.source` marker for a point created from the legacy
/// campaign recipient list.
pub const LEGACY_RECIPIENT_SOURCE: &str = "legacy_campaign";

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

/// PostgreSQL-backed campaign manager for the legacy/CP compatibility model.
///
/// Campaigns and recipients are persisted across restarts. This manager never
/// sends mail: see the module docs.
#[derive(Debug, Clone)]
pub struct CampaignManager {
    db: PgPool,
    max_campaigns: usize,
}

impl CampaignManager {
    pub fn new(max_campaigns: usize, db: PgPool) -> Self {
        Self { db, max_campaigns }
    }

    /// The underlying pool (used by read/reporting helpers).
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

        // F85: create the campaign's initial optimization arm through the
        // production campaign workflow — the canonical campaign_arms store
        // (migration 197) is populated by its producer, never by ad-hoc
        // writes. ensure_arms is idempotent; the lazy redis pool is only
        // touched by selection/cache paths, not by arm creation.
        let autopilot_redis = deadpool_redis::Config::from_url(
            crate::config::SalesConfig::default().redis_url.clone(),
        )
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .map_err(|e| SalesError::Database(format!("autopilot redis pool: {e}")))?;
        analytics::campaign_autopilot::CampaignAutopilot::new(self.db.clone(), autopilot_redis)
            .ensure_arms(
                &campaign.tenant_id,
                &campaign.id.to_string(),
                std::slice::from_ref(&campaign.template_id),
            )
            .await
            .map_err(|e| {
                SalesError::Database(format!("campaign arm initialization failed: {e}"))
            })?;

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

    /// Transition a draft/paused campaign to Active and materialize its
    /// recipients into canonical enrollments.
    ///
    /// # Behaviour (release-blocker: one send engine)
    ///
    /// This is the compatibility-planner boundary: it never sends mail. In
    /// order it
    ///
    /// 1. resolves the approved, in-date `sales_jurisdiction_policies` email
    ///    policy for the recipients' jurisdiction — with no approved policy it
    ///    REFUSES the start (before any state change) instead of bypassing the
    ///    legal gate;
    /// 2. atomically transitions the campaign to Active (SA-13 tenant-scoped
    ///    conditional UPDATE plus the max-active-campaigns check);
    /// 3. materializes one canonical compatibility sequence per campaign
    ///    (keyed by `sales_sequences.legacy_campaign_id`, so restarting reuses
    ///    it), one contact + email contact point per recipient (a legacy
    ///    recipient is `verification = 'unknown'`, never `valid`) and enrolls
    ///    every contact through [`crate::enrollments::start_outreach`].
    ///
    /// Enrollment happens after the status commit (the same ordering the old
    /// dispatch used), and re-running the start is idempotent: `start_outreach`
    /// reports `already_enrolled` and creates no duplicate actions. A rejected
    /// recipient is never handed to a direct-send fallback.
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
    ///
    /// Callers that render the per-recipient outcome (accepted / rejected /
    /// rejection reasons) should use [`Self::start_campaign_with_outreach`];
    /// this method keeps the `Campaign` return type for existing callers.
    pub async fn start_campaign(&self, tenant_id: &str, id: Uuid) -> Result<Campaign, SalesError> {
        let (campaign, _outreach) = self.start_campaign_with_outreach(tenant_id, id).await?;
        Ok(campaign)
    }

    /// [`Self::start_campaign`], returning the canonical enrollment outcome.
    ///
    /// `None` when the campaign has no recipients (nothing to enroll). The
    /// response reports exactly how many recipients were accepted and the
    /// rejection-reason keys for those that were not — enrollment rejections
    /// (suppression, legal policy, unverified contact, already enrolled) are
    /// never silently converted into a direct send.
    pub async fn start_campaign_with_outreach(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<(Campaign, Option<StartOutreachResponse>), SalesError> {
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

        match campaign.status {
            CampaignStatus::Draft | CampaignStatus::Paused => {
                // Normalized, de-duplicated legacy recipient list. Every
                // address becomes a canonical contact whose gates the
                // enrollment machinery evaluates.
                let emails: Vec<String> = sqlx::query_scalar(
                    "SELECT DISTINCT LOWER(BTRIM(r.email)) FROM sales_campaign_recipients r \
                     JOIN sales_campaigns c ON c.id = r.campaign_id \
                     WHERE r.campaign_id = $1 AND c.tenant_id = $2 \
                     ORDER BY 1",
                )
                .bind(id)
                .bind(tenant_id)
                .fetch_all(&self.db)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?
                .into_iter()
                .filter(|email: &String| !email.is_empty())
                .collect();

                // Legal basis FIRST: resolve the approved autonomy policy
                // before any state change. If none resolves, the start is
                // refused and the campaign stays draft/paused.
                let autonomy_policy_id = if emails.is_empty() {
                    None
                } else {
                    Some(self.resolve_autonomy_policy_id(tenant_id, &emails).await?)
                };

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

                // Canonical materialization + enrollment, AFTER the status
                // commit (same ordering the old dispatch used): every accepted
                // recipient becomes a canonical enrollment whose first step
                // action is queued for the durable worker. Rejections are
                // reported, never re-routed to a direct send.
                let outreach = match autonomy_policy_id {
                    None => None,
                    Some(policy_id) => Some(
                        self.enroll_campaign_recipients(tenant_id, &campaign, policy_id, &emails)
                            .await?,
                    ),
                };

                if let Some(ref outcome) = outreach {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        campaign_id = %id,
                        accepted = outcome.accepted,
                        rejected = outcome.rejected,
                        "campaign start materialized canonical enrollments"
                    );
                    if outcome.rejected > 0 {
                        tracing::warn!(
                            tenant_id = %tenant_id,
                            campaign_id = %id,
                            rejection_reasons = ?outcome.rejection_reasons,
                            "campaign start: some recipients could not be enrolled — \
                             they are NOT sent to directly"
                        );
                    }
                }

                Ok((updated, outreach))
            }
            _ => Err(SalesError::InvalidInput(format!(
                "cannot start campaign in status {}",
                campaign.status
            ))),
        }
    }

    /// Enroll every materialized campaign recipient through the ONE canonical
    /// entry point, [`crate::enrollments::start_outreach`] — the same gates
    /// `/enrollments` uses (existence, email, suppression, legal policy,
    /// verification, duplicate enrollment). Chunked to the outreach command's
    /// per-call bound; the aggregate response reports the exact per-reason
    /// rejection counts.
    async fn enroll_campaign_recipients(
        &self,
        tenant_id: &str,
        campaign: &Campaign,
        autonomy_policy_id: Uuid,
        emails: &[String],
    ) -> Result<StartOutreachResponse, SalesError> {
        let sequence_id = self
            .materialize_compatibility_sequence(tenant_id, campaign)
            .await?;
        let contact_ids = self.materialize_contacts(tenant_id, emails).await?;
        let queue = ActionQueue::new(
            self.db.clone(),
            format!("legacy-campaign-compat-{tenant_id}"),
        );

        let mut aggregate: Option<StartOutreachResponse> = None;
        for chunk in contact_ids.chunks(enrollments::MAX_OUTREACH_CONTACTS) {
            let request = StartOutreachRequest {
                sequence_id,
                contact_ids: chunk.to_vec(),
                autonomy_policy_id,
                experiment_id: None,
            };
            let response =
                enrollments::start_outreach(&self.db, &queue, tenant_id, &request).await?;
            match &mut aggregate {
                Some(total) => {
                    total.accepted += response.accepted;
                    total.rejected += response.rejected;
                    for (reason, count) in response.rejection_reasons {
                        *total.rejection_reasons.entry(reason).or_insert(0) += count;
                    }
                }
                None => aggregate = Some(response),
            }
        }

        aggregate.ok_or_else(|| {
            SalesError::Internal(anyhow::anyhow!(
                "campaign {} start produced no enrollment batch",
                campaign.id
            ))
        })
    }

    /// Materialize canonical contacts + email contact points for the legacy
    /// recipient list, returning their contact ids (de-duplicated, order
    /// preserving).
    async fn materialize_contacts(
        &self,
        tenant_id: &str,
        emails: &[String],
    ) -> Result<Vec<Uuid>, SalesError> {
        let mut seen: HashSet<Uuid> = HashSet::with_capacity(emails.len());
        let mut contact_ids = Vec::with_capacity(emails.len());
        for email in emails {
            let contact_id = self
                .find_or_create_contact_for_email(tenant_id, email)
                .await?;
            if seen.insert(contact_id) {
                contact_ids.push(contact_id);
            }
        }
        Ok(contact_ids)
    }

    /// Find the canonical contact for an email address, or create one.
    ///
    /// * An existing `sales_contact_points` row for
    ///   `(tenant_id, 'email', normalized_value)` always wins: the legacy
    ///   recipient reuses that contact and its verification provenance,
    ///   instead of creating a second contact for the same address.
    /// * A new contact is associated with the account resolved from the
    ///   address's domain when a `sales_accounts` row exists; otherwise
    ///   `account_id` stays NULL (a legacy contact migrates without inventing
    ///   a company).
    /// * A newly created point is `verification = 'unknown'` with a low,
    ///   documented confidence — a legacy campaign recipient carries no
    ///   verification provenance and is NEVER claimed `valid`.
    async fn find_or_create_contact_for_email(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Uuid, SalesError> {
        let normalized = normalize_recipient_email(email);

        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT contact_id FROM sales_contact_points \
             WHERE tenant_id = $1 AND channel = 'email' AND normalized_value = $2",
        )
        .bind(tenant_id)
        .bind(&normalized)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        if let Some(contact_id) = existing {
            return Ok(contact_id);
        }

        let account_id: Option<Uuid> = match email_domain(&normalized) {
            Some(domain) => sqlx::query_scalar(
                "SELECT id FROM sales_accounts \
                 WHERE tenant_id = $1 AND LOWER(domain) = $2 \
                 LIMIT 1",
            )
            .bind(tenant_id)
            .bind(&domain)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?,
            None => None,
        };

        // Contact + point commit together; the point's unique
        // `(tenant_id, channel, normalized_value)` makes concurrent starts
        // safe: the loser rolls its contact back and reuses the winner's.
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
        let contact_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) \
             VALUES ($1, $2, $3, '')",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let inserted: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO sales_contact_points \
                 (id, tenant_id, contact_id, channel, value, normalized_value, \
                  verification, verification_provider, confidence, source) \
             VALUES ($1, $2, $3, 'email', $4, $4, $5, NULL, $6, $7) \
             ON CONFLICT (tenant_id, channel, normalized_value) DO NOTHING \
             RETURNING contact_id",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(contact_id)
        .bind(&normalized)
        .bind(LEGACY_RECIPIENT_VERIFICATION)
        .bind(LEGACY_RECIPIENT_CONFIDENCE)
        .bind(LEGACY_RECIPIENT_SOURCE)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        match inserted {
            Some(inserted_contact_id) => {
                tx.commit()
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;
                Ok(inserted_contact_id)
            }
            None => {
                tx.rollback()
                    .await
                    .map_err(|e| SalesError::Database(e.to_string()))?;
                sqlx::query_scalar(
                    "SELECT contact_id FROM sales_contact_points \
                     WHERE tenant_id = $1 AND channel = 'email' AND normalized_value = $2",
                )
                .bind(tenant_id)
                .bind(&normalized)
                .fetch_one(&self.db)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))
            }
        }
    }

    /// Create or reuse the campaign's canonical compatibility sequence.
    ///
    /// Keyed by `sales_sequences.legacy_campaign_id` (unique per tenant via
    /// `idx_sales_sequences_legacy_campaign`), so starting/restarting the same
    /// campaign always adapts the SAME sequence instead of creating a new one.
    /// The active version and its single email step (carrying the campaign's
    /// template) are upserted idempotently.
    async fn materialize_compatibility_sequence(
        &self,
        tenant_id: &str,
        campaign: &Campaign,
    ) -> Result<Uuid, SalesError> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        let sequence_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sales_sequences \
                 (id, tenant_id, name, description, status, legacy_campaign_id) \
             VALUES ($1, $2, $3, $4, 'active', $5) \
             ON CONFLICT (tenant_id, legacy_campaign_id) WHERE legacy_campaign_id IS NOT NULL \
             DO UPDATE SET name = EXCLUDED.name, status = 'active', updated_at = NOW() \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(format!("Legacy campaign: {}", campaign.name))
        .bind(format!(
            "Compatibility sequence materialized from sales_campaigns.id = {}",
            campaign.id
        ))
        .bind(campaign.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let version_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sales_sequence_versions \
                 (id, tenant_id, sequence_id, version, status, locale, approved_by, approved_at) \
             VALUES ($1, $2, $3, 1, 'active', 'en', 'legacy-campaign-compat', NOW()) \
             ON CONFLICT (sequence_id, version) DO UPDATE \
                SET status = 'active', \
                    approved_by = COALESCE(sales_sequence_versions.approved_by, EXCLUDED.approved_by), \
                    approved_at = COALESCE(sales_sequence_versions.approved_at, EXCLUDED.approved_at) \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(sequence_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        sqlx::query(
            "INSERT INTO sales_sequence_steps \
                 (id, tenant_id, version_id, step_index, kind, template_id, \
                  min_delay_secs, max_delay_secs) \
             VALUES ($1, $2, $3, 0, 'email', $4, 0, 0) \
             ON CONFLICT (version_id, step_index) DO UPDATE \
                SET template_id = EXCLUDED.template_id",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(version_id)
        .bind(&campaign.template_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(sequence_id)
    }

    /// Resolve the approved, in-date autonomy policy for the contacts'
    /// jurisdiction.
    ///
    /// The recipients' jurisdiction evidence is the account matched by the
    /// recipient address's domain: one distinct country → that jurisdiction;
    /// none or several → the fail-closed `UNKNOWN` policy row. No policy id is
    /// ever invented: when no approved, in-date, email-channel policy exists
    /// (including a `prohibited` one), the start is refused with
    /// [`SalesError::PolicyDenied`] rather than bypassing the legal gate.
    async fn resolve_autonomy_policy_id(
        &self,
        tenant_id: &str,
        emails: &[String],
    ) -> Result<Uuid, SalesError> {
        let jurisdictions: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT UPPER(BTRIM(a.country)) FROM sales_accounts a \
             WHERE a.tenant_id = $1 \
               AND a.country IS NOT NULL AND BTRIM(a.country) <> '' \
               AND LOWER(a.domain) IN ( \
                   SELECT LOWER(SPLIT_PART(e, '@', 2)) FROM UNNEST($2::text[]) AS e \
               )",
        )
        .bind(tenant_id)
        .bind(emails)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        let jurisdiction = if jurisdictions.len() == 1 {
            jurisdictions[0].clone()
        } else {
            "UNKNOWN".to_string()
        };

        let policy_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT p.id FROM sales_jurisdiction_policies p \
             WHERE p.channel = 'email' \
               AND p.jurisdiction = $1 \
               AND p.approved_by IS NOT NULL AND p.approved_at IS NOT NULL \
               AND p.valid_from <= NOW() \
               AND (p.valid_until IS NULL OR p.valid_until > NOW()) \
               AND p.decision IN ('allowed', 'approval_required') \
             ORDER BY p.version DESC, p.created_at DESC \
             LIMIT 1",
        )
        .bind(&jurisdiction)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        policy_id.ok_or_else(|| {
            SalesError::PolicyDenied(format!(
                "no approved, in-date email jurisdiction policy for '{jurisdiction}' — \
                 refusing to start the campaign: the legal gate cannot be satisfied"
            ))
        })
    }

    /// Due-legacy-recipient rows for the dry-run preview: not yet sent, not
    /// suppressed, within the frequency cap, enriched with the CRM lead
    /// profile. Read-only reporting for the CP — this never feeds a send path.
    async fn due_recipient_rows(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(String, LeadProfile)>, SalesError> {
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
                     WHERE u.tenant_id = c.tenant_id AND LOWER(u.email) = LOWER(r.email)\
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
                (
                    email,
                    LeadProfile {
                        name: name.unwrap_or_default(),
                        company: company.unwrap_or_default(),
                        title: title.unwrap_or_default(),
                    },
                )
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
                    WHERE u.tenant_id = c.tenant_id AND LOWER(u.email) = LOWER(r.email))), \
                COUNT(*) FILTER (WHERE r.sent_at IS NULL AND NOT EXISTS (\
                    SELECT 1 FROM sales_unsubscribes u \
                    WHERE u.tenant_id = c.tenant_id AND LOWER(u.email) = LOWER(r.email)) AND EXISTS (\
                    SELECT 1 FROM suppressions s \
                    WHERE s.tenant_id = c.tenant_id AND LOWER(s.email) = LOWER(r.email))), \
                COUNT(*) FILTER (WHERE r.sent_at IS NULL AND NOT EXISTS (\
                    SELECT 1 FROM sales_unsubscribes u \
                    WHERE u.tenant_id = c.tenant_id AND LOWER(u.email) = LOWER(r.email)) AND NOT EXISTS (\
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
                    WHERE u.tenant_id = c.tenant_id AND LOWER(u.email) = LOWER(r.email)) AND NOT EXISTS (\
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

        // Render previews for up to `sample_limit` due legacy recipients. The
        // unsubscribe link is derived from the production dispatcher's signing
        // config; nothing here is enqueued.
        let mut preview = Vec::new();
        if let Some(p) = prod {
            if let Ok(template_content) =
                crate::dispatcher::fetch_template(&self.db, tenant_id, &campaign.template_id).await
            {
                let sample = self
                    .due_recipient_rows(tenant_id, campaign_id, sample_limit as i64)
                    .await
                    .unwrap_or_default();
                for (email, lead) in sample {
                    let unsubscribe_link = legacy_unsubscribe_link(p.config(), tenant_id, &email);
                    let recipient = DispatchRecipient {
                        email,
                        unsubscribe_link,
                        lead: Some(lead),
                    };
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
            let normalized = normalize_recipient_email(&email);
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

/// Normalize a recipient address for canonical contact-point matching:
/// trim surrounding whitespace and lowercase. This is the exact form stored
/// in `sales_contact_points.normalized_value`.
fn normalize_recipient_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// The domain part of a normalized address, when it is a syntactically
/// plausible address. Used only to resolve an existing canonical account;
/// `None` means the contact migrates with a NULL `account_id`.
fn email_domain(normalized_email: &str) -> Option<String> {
    if !is_valid_recipient_email(normalized_email) {
        return None;
    }
    normalized_email
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_ascii_lowercase())
}

/// A CAN-SPAM unsubscribe link for dry-run previews, signed exactly like the
/// dispatcher signs it for real sends. Reporting only — never enqueued here.
fn legacy_unsubscribe_link(
    config: &crate::config::DispatchConfig,
    tenant_id: &str,
    email: &str,
) -> String {
    let token = sign_unsubscribe_token_default_ttl(
        &config.unsubscribe_secret,
        tenant_id,
        &normalize_recipient_email(email),
    );
    format!("{}/u/{}", config.public_base_url, token)
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
    use crate::test_db::{canonical_test_pool, unique_test_tenant};

    /// Manager on the canonical provisioned test database (fresh pool per
    /// test). No dispatcher is needed any more: `start_campaign` materializes
    /// canonical enrollments instead of sending. These tests start campaigns
    /// with no recipients, so no jurisdiction policy or enrollment work is
    /// required either.
    async fn make_mgr(test_name: &str) -> Option<CampaignManager> {
        make_mgr_with_limit(test_name, 10).await
    }

    async fn make_mgr_with_limit(test_name: &str, max_campaigns: usize) -> Option<CampaignManager> {
        let db = canonical_test_pool(test_name).await?;
        Some(CampaignManager::new(max_campaigns, db))
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_create_and_list() {
        let Some(mgr) = make_mgr("campaigns::tests::test_create_and_list").await else {
            return;
        };
        let tenant = unique_test_tenant("campaign-list");
        let other_tenant = unique_test_tenant("campaign-list-other");
        let c = mgr
            .create_campaign(
                tenant.clone(),
                "Welcome".into(),
                "tmpl_1".into(),
                "all_leads".into(),
            )
            .await
            .unwrap();
        assert_eq!(c.status, CampaignStatus::Draft);
        let list = mgr.list_campaigns(&tenant, 100, 0).await.unwrap();
        assert!(!list.is_empty());
        assert!(mgr
            .list_campaigns(&other_tenant, 100, 0)
            .await
            .unwrap()
            .is_empty());
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_start_pause_lifecycle() {
        let Some(mgr) = make_mgr("campaigns::tests::test_start_pause_lifecycle").await else {
            return;
        };
        let tenant = unique_test_tenant("campaign-lifecycle");
        let c = mgr
            .create_campaign(
                tenant.clone(),
                "Drip".into(),
                "tmpl_2".into(),
                "new_leads".into(),
            )
            .await
            .unwrap();
        let started = mgr.start_campaign(&tenant, c.id).await.unwrap();
        assert_eq!(started.status, CampaignStatus::Active);

        let paused = mgr.pause_campaign(&tenant, c.id).await.unwrap();
        assert_eq!(paused.status, CampaignStatus::Paused);

        // re-start after pause
        let restarted = mgr.start_campaign(&tenant, c.id).await.unwrap();
        assert_eq!(restarted.status, CampaignStatus::Active);
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_max_campaigns_enforced() {
        let Some(mgr) =
            make_mgr_with_limit("campaigns::tests::test_max_campaigns_enforced", 1).await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-max");
        let c = mgr
            .create_campaign(tenant.clone(), "C1".into(), "t".into(), "a".into())
            .await
            .unwrap();
        mgr.start_campaign(&tenant, c.id).await.unwrap();

        // second active campaign should be rejected
        let c2 = mgr
            .create_campaign(tenant.clone(), "C2".into(), "t".into(), "a".into())
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
        let Some(mgr) =
            make_mgr_with_limit("campaigns::tests::test_max_campaigns_enforced_at_start", 1).await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-max-start");

        // Two drafts both pass the create-time check (zero active campaigns).
        let c1 = mgr
            .create_campaign(tenant.clone(), "C1".into(), "t".into(), "a".into())
            .await
            .unwrap();
        let c2 = mgr
            .create_campaign(tenant.clone(), "C2".into(), "t".into(), "a".into())
            .await
            .unwrap();

        mgr.start_campaign(&tenant, c1.id).await.unwrap();

        // Starting the second draft must be rejected by the start-time check.
        assert!(matches!(
            mgr.start_campaign(&tenant, c2.id).await,
            Err(SalesError::MaxCampaignsReached(1))
        ));
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_recipients_and_stats() {
        let Some(mgr) = make_mgr("campaigns::tests::test_recipients_and_stats").await else {
            return;
        };
        let tenant = unique_test_tenant("campaign-stats");
        let c = mgr
            .create_campaign(
                tenant.clone(),
                "Outreach".into(),
                "tmpl".into(),
                "saas".into(),
            )
            .await
            .unwrap();
        let added = mgr
            .add_recipients(&tenant, c.id, vec!["a@x.com".into(), "b@x.com".into()])
            .await
            .unwrap();
        assert_eq!(added, 2);

        let stats = mgr.get_stats(&tenant, c.id).await.unwrap();
        assert_eq!(stats["recipients"], 2);
        assert_eq!(stats["sent"], 0);
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_campaign_operations_are_tenant_scoped() {
        let Some(mgr) =
            make_mgr("campaigns::tests::test_campaign_operations_are_tenant_scoped").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-scope");
        let other_tenant = unique_test_tenant("campaign-scope-other");
        let campaign = mgr
            .create_campaign(tenant.clone(), "Scoped".into(), "tmpl".into(), "all".into())
            .await
            .unwrap();

        assert!(matches!(
            mgr.start_campaign(&other_tenant, campaign.id).await,
            Err(SalesError::CampaignNotFound(id)) if id == campaign.id
        ));
        assert!(matches!(
            mgr.add_recipients(&other_tenant, campaign.id, vec!["user@example.com".into()]).await,
            Err(SalesError::CampaignNotFound(id)) if id == campaign.id
        ));
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_add_recipients_deduplicates_addresses() {
        let Some(mgr) =
            make_mgr("campaigns::tests::test_add_recipients_deduplicates_addresses").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-dedup");
        let campaign = mgr
            .create_campaign(tenant.clone(), "Scoped".into(), "tmpl".into(), "all".into())
            .await
            .unwrap();

        let added = mgr
            .add_recipients(
                &tenant,
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
        let stats = mgr.get_stats(&tenant, campaign.id).await.unwrap();
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

    // ── Legacy campaign → canonical mapping (one send engine) ───────────

    /// The legacy recipient normalization is the canonical contact-point
    /// `normalized_value` form: trimmed + lowercased.
    #[test]
    fn legacy_recipient_normalization_trims_and_lowercases() {
        assert_eq!(
            normalize_recipient_email(" Alice@Example.COM "),
            "alice@example.com"
        );
        assert_eq!(
            normalize_recipient_email("bob@example.com"),
            "bob@example.com"
        );
        assert!(normalize_recipient_email("   ").is_empty());
    }

    /// Domain resolution for the account association: only a syntactically
    /// plausible address yields a domain; anything else leaves `account_id`
    /// NULL rather than guessing a company.
    #[test]
    fn legacy_recipient_domain_requires_a_valid_address() {
        assert_eq!(
            email_domain("alice@Example.COM"),
            Some("example.com".to_string())
        );
        assert_eq!(email_domain("no-at-sign"), None);
        assert_eq!(email_domain("a@b"), None);
        assert_eq!(email_domain("alice@"), None);
    }

    /// A point materialized from a legacy campaign recipient carries no
    /// verification provenance and must NEVER be recorded as `valid`.
    #[test]
    fn legacy_recipient_point_never_claims_valid() {
        assert_ne!(LEGACY_RECIPIENT_VERIFICATION, "valid");
        assert_eq!(LEGACY_RECIPIENT_VERIFICATION, "unknown");
        assert!(
            LEGACY_RECIPIENT_CONFIDENCE > 0.0 && LEGACY_RECIPIENT_CONFIDENCE <= 0.25,
            "the confidence must be documented as low"
        );
        assert_eq!(LEGACY_RECIPIENT_SOURCE, "legacy_campaign");
    }

    /// Create a contact with an already-verified email point, so the legacy
    /// recipient has canonical provenance the compatibility path must reuse.
    async fn seed_verified_point(pool: &PgPool, tenant: &str, email: &str) -> Uuid {
        let contact_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, full_name) \
             VALUES ($1, $2, 'Existing Contact')",
        )
        .bind(contact_id)
        .bind(tenant)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_contact_points \
                 (id, tenant_id, contact_id, channel, value, normalized_value, \
                  verification, confidence) \
             VALUES ($1, $2, $3, 'email', $4, LOWER($4), 'valid', 0.9)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(contact_id)
        .bind(email)
        .execute(pool)
        .await
        .unwrap();
        contact_id
    }

    async fn scalar_count(pool: &PgPool, sql: &str, tenant: &str) -> i64 {
        sqlx::query_scalar(sql)
            .bind(tenant)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn cleanup_campaign_fixture(pool: &PgPool, tenant: &str) {
        for statement in [
            "DELETE FROM sales_actions WHERE tenant_id = $1",
            "DELETE FROM sales_step_executions WHERE tenant_id = $1",
            "DELETE FROM sales_enrollments WHERE tenant_id = $1",
            "DELETE FROM sales_sequence_steps WHERE tenant_id = $1",
            "DELETE FROM sales_sequence_versions WHERE tenant_id = $1",
            "DELETE FROM sales_sequences WHERE tenant_id = $1",
            "DELETE FROM sales_contact_points WHERE tenant_id = $1",
            "DELETE FROM sales_contacts WHERE tenant_id = $1",
            "DELETE FROM sales_accounts WHERE tenant_id = $1",
            "DELETE FROM sales_campaigns WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(tenant)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    /// Live DB (canonical schema): starting a campaign twice materializes
    /// exactly ONE compatibility sequence and enrolls exactly ONCE, and the
    /// enqueue goes through the durable `sales_actions` queue — never into
    /// `email_queue` directly.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn campaign_start_materializes_one_sequence_and_never_duplicates_enrollment() {
        let Some(pool) =
            canonical_test_pool("campaigns::tests::campaign_start_materializes_one_sequence").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-compat");
        let mgr = CampaignManager::new(10, pool.clone());
        let email = format!("legacy-{}@example.com", &tenant[..12]);
        seed_verified_point(&pool, &tenant, &email).await;

        let campaign = mgr
            .create_campaign(
                tenant.clone(),
                "Compat".into(),
                "tmpl_compat".into(),
                "all".into(),
            )
            .await
            .unwrap();
        mgr.add_recipients(&tenant, campaign.id, vec![email.clone()])
            .await
            .unwrap();

        let (started, first) = mgr
            .start_campaign_with_outreach(&tenant, campaign.id)
            .await
            .unwrap();
        assert_eq!(started.status, CampaignStatus::Active);
        let first = first.expect("recipients exist, so an enrollment batch must run");
        assert_eq!(
            first.accepted, 1,
            "the verified canonical point must enroll"
        );
        assert_eq!(first.rejected, 0);

        let campaign_id = campaign.id;
        let sequences: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_sequences \
             WHERE tenant_id = $1 AND legacy_campaign_id = $2",
        )
        .bind(&tenant)
        .bind(campaign_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sequences, 1, "one compatibility sequence per campaign");
        let sequence_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM sales_sequences WHERE tenant_id = $1 AND legacy_campaign_id = $2",
        )
        .bind(&tenant)
        .bind(campaign_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            scalar_count(
                &pool,
                "SELECT COUNT(*) FROM sales_enrollments WHERE tenant_id = $1",
                &tenant
            )
            .await,
            1
        );
        assert_eq!(
            scalar_count(
                &pool,
                "SELECT COUNT(*) FROM sales_actions \
                 WHERE tenant_id = $1 AND action_type = 'send_step'",
                &tenant
            )
            .await,
            1,
            "the campaign send must be a durable send_step action"
        );
        let queued_directly: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM email_queue WHERE \"to\" = $1")
                .bind(&email)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            queued_directly, 0,
            "campaign start must NOT enqueue into email_queue directly"
        );

        // Restart: pause then start again. The same sequence is reused and the
        // live enrollment reports already_enrolled instead of duplicating.
        mgr.pause_campaign(&tenant, campaign.id).await.unwrap();
        let (_restarted, second) = mgr
            .start_campaign_with_outreach(&tenant, campaign.id)
            .await
            .unwrap();
        let second = second.expect("recipients still exist");
        assert_eq!(second.accepted, 0);
        assert_eq!(second.rejected, 1);
        assert_eq!(
            second.rejection_reasons.get("already_enrolled"),
            Some(&1),
            "a re-start must report already_enrolled, not send again"
        );

        let sequences: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_sequences \
             WHERE tenant_id = $1 AND legacy_campaign_id = $2",
        )
        .bind(&tenant)
        .bind(campaign_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let sequences_by_id: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_sequences WHERE id = $1")
                .bind(sequence_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sequences, 1);
        assert_eq!(
            sequences_by_id, 1,
            "the same compatibility sequence is reused"
        );
        assert_eq!(
            scalar_count(
                &pool,
                "SELECT COUNT(*) FROM sales_enrollments WHERE tenant_id = $1",
                &tenant
            )
            .await,
            1
        );
        assert_eq!(
            scalar_count(
                &pool,
                "SELECT COUNT(*) FROM sales_actions \
                 WHERE tenant_id = $1 AND action_type = 'send_step'",
                &tenant
            )
            .await,
            1,
            "a re-start must not duplicate queued actions"
        );

        cleanup_campaign_fixture(&pool, &tenant).await;
    }

    /// Live DB (canonical schema): a legacy recipient whose address normalizes
    /// to an existing canonical contact point reuses that contact (and its
    /// verification provenance) instead of creating a second contact.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn campaign_start_reuses_existing_contact_point_and_contact() {
        let Some(pool) =
            canonical_test_pool("campaigns::tests::campaign_start_reuses_existing_point").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-reuse");
        let mgr = CampaignManager::new(10, pool.clone());
        let email = format!("Reuse-{}@Example.com", &tenant[..12]);
        let existing_contact_id =
            seed_verified_point(&pool, &tenant, &email.to_ascii_lowercase()).await;

        let campaign = mgr
            .create_campaign(tenant.clone(), "Reuse".into(), "t".into(), "all".into())
            .await
            .unwrap();
        mgr.add_recipients(&tenant, campaign.id, vec![email])
            .await
            .unwrap();

        let (_, outcome) = mgr
            .start_campaign_with_outreach(&tenant, campaign.id)
            .await
            .unwrap();
        let outcome = outcome.expect("recipients exist");
        assert_eq!(outcome.accepted, 1);

        let points: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_contact_points \
             WHERE tenant_id = $1 AND channel = 'email' AND normalized_value = $2",
        )
        .bind(&tenant)
        .bind(format!("reuse-{}@example.com", &tenant[..12]))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            points, 1,
            "the existing point must be reused, not duplicated"
        );

        let contacts: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_contacts WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(contacts, 1, "no second contact may be created");

        let enrolled_contact: Uuid =
            sqlx::query_scalar("SELECT contact_id FROM sales_enrollments WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(enrolled_contact, existing_contact_id);

        cleanup_campaign_fixture(&pool, &tenant).await;
    }

    /// Live DB (canonical schema): a legacy recipient with no matching
    /// `sales_accounts` row migrates with `account_id = NULL` (never an
    /// invented company) and its new point is `unknown`, not `valid`.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn campaign_start_creates_unknown_point_with_null_account() {
        let Some(pool) =
            canonical_test_pool("campaigns::tests::campaign_start_unknown_point").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-unknown");
        let mgr = CampaignManager::new(10, pool.clone());
        let email = format!("nobody-{}@no-such-account.test", &tenant[..12]);

        let campaign = mgr
            .create_campaign(tenant.clone(), "Unknown".into(), "t".into(), "all".into())
            .await
            .unwrap();
        mgr.add_recipients(&tenant, campaign.id, vec![email.clone()])
            .await
            .unwrap();

        let (started, outcome) = mgr
            .start_campaign_with_outreach(&tenant, campaign.id)
            .await
            .unwrap();
        assert_eq!(started.status, CampaignStatus::Active);
        let outcome = outcome.expect("recipients exist");
        // The created point is `unknown`, so the canonical verification gate
        // rejects the enrollment — it is NEVER silently treated as valid.
        assert_eq!(outcome.accepted, 0);
        assert_eq!(outcome.rejected, 1);
        assert_eq!(
            outcome.rejection_reasons.get("unverified_contact"),
            Some(&1)
        );

        let (verification, confidence, account_id): (String, f64, Option<Uuid>) = sqlx::query_as(
            "SELECT p.verification, p.confidence, c.account_id \
                 FROM sales_contact_points p \
                 JOIN sales_contacts c ON c.id = p.contact_id \
                 WHERE p.tenant_id = $1 AND p.normalized_value = $2",
        )
        .bind(&tenant)
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(verification, "unknown", "a legacy point is never `valid`");
        assert!(
            confidence <= 0.25,
            "legacy confidence must stay documented-low"
        );
        assert!(account_id.is_none(), "no company may be invented");

        assert_eq!(
            scalar_count(
                &pool,
                "SELECT COUNT(*) FROM sales_actions WHERE tenant_id = $1",
                &tenant
            )
            .await,
            0,
            "nothing may be enqueued for a rejected recipient"
        );

        cleanup_campaign_fixture(&pool, &tenant).await;
    }

    /// Live DB (canonical schema): a campaign whose recipients' jurisdiction
    /// has no approved, in-date email policy refuses to start instead of
    /// enrolling (the legal gate is never bypassed).
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn campaign_start_without_approved_jurisdiction_policy_is_refused() {
        let Some(pool) =
            canonical_test_pool("campaigns::tests::campaign_start_policy_refused").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-policy");
        let mgr = CampaignManager::new(10, pool.clone());

        // A jurisdiction with no policy row, attached to the recipient's
        // domain so the resolver picks it.
        let domain = format!("{}.invalid", &tenant[..12]);
        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, country) \
             VALUES ($1, $2, 'Policy Test Co', $3, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant)
        .bind(&domain)
        .bind(format!("TST-{}", &tenant[..12]))
        .execute(&pool)
        .await
        .unwrap();

        let campaign = mgr
            .create_campaign(tenant.clone(), "Policy".into(), "t".into(), "all".into())
            .await
            .unwrap();
        mgr.add_recipients(&tenant, campaign.id, vec![format!("a@{domain}")])
            .await
            .unwrap();

        let refused = mgr.start_campaign(&tenant, campaign.id).await;
        assert!(
            matches!(refused, Err(SalesError::PolicyDenied(_))),
            "no approved policy must refuse the start: {refused:?}"
        );

        let status: String = sqlx::query_scalar("SELECT status FROM sales_campaigns WHERE id = $1")
            .bind(campaign.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "draft", "the campaign must not become active");
        assert_eq!(
            scalar_count(
                &pool,
                "SELECT COUNT(*) FROM sales_enrollments WHERE tenant_id = $1",
                &tenant
            )
            .await,
            0,
            "a refused start must not enroll anyone"
        );
        assert_eq!(
            scalar_count(
                &pool,
                "SELECT COUNT(*) FROM sales_actions WHERE tenant_id = $1",
                &tenant
            )
            .await,
            0
        );

        cleanup_campaign_fixture(&pool, &tenant).await;
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
        let Some(db) = canonical_test_pool(
            "campaigns::tests::reconcile_sent_counter_follows_events_or_falls_back",
        )
        .await
        else {
            return;
        };
        let tenant = unique_test_tenant("stats-f");
        let manager = CampaignManager::new(10, db.clone());
        let campaign = manager
            .create_campaign(tenant.clone(), "stats".into(), "t".into(), "all".into())
            .await
            .unwrap();
        manager
            .add_recipients(
                &tenant,
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
            .bind(&tenant)
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
