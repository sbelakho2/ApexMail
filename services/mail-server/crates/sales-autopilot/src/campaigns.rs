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
//!
//! Starting is a durable, resumable operation (`start_state` /
//! `start_operation_id`, migration 216): a draft/paused campaign is admitted
//! under a tenant-scoped advisory lock, materialized idempotently, and only
//! becomes `active` once at least one contact can actually be sent to.
//! Failures stay resumable in `starting`; a batch that accepted zero contacts
//! parks in `verification_pending` instead of activating. The policy is
//! resolved by the canonical store per contact — never as one batch-level
//! `autonomy_policy_id`.

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

// ---------------------------------------------------------------------------
// Durable start-operation state
// ---------------------------------------------------------------------------

/// Phase of a campaign start operation.
///
/// `sales_campaigns.status` keeps the legacy CP vocabulary
/// (`draft`/`active`/`paused`/`completed`); the start operation is layered over
/// it so a failed or partially-completed start is never misreported as active:
///
/// * [`CampaignStartPhase::Starting`] — persisted as
///   `sales_campaigns.start_state = 'starting'` with a durable
///   `start_operation_id`. Enrollment materialization is in flight; the
///   campaign is NOT active. A failure or crash leaves this state in place and
///   the next call resumes the same operation id.
/// * [`CampaignStartPhase::VerificationPending`] — persisted as
///   `start_state = 'verification_pending'`. Enrollment completed but zero
///   contacts were accepted, so the campaign is NOT active: an "active"
///   campaign whose every recipient was rejected advertises sends that can
///   never happen. The operator-readable reason is in
///   `sales_campaigns.last_error` and in the start response.
/// * [`CampaignStartPhase::Active`] — terminal success: `status = 'active'`,
///   `start_state IS NULL`; the operation id is retained for audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignStartPhase {
    Starting,
    VerificationPending,
    Active,
}

impl CampaignStartPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::VerificationPending => "verification_pending",
            Self::Active => "active",
        }
    }

    /// Parse a persisted `sales_campaigns.start_state` value. `active` is never
    /// persisted in that column (it is expressed by `status = 'active'`).
    fn parse_durable(raw: &str) -> Option<Self> {
        match raw {
            "starting" => Some(Self::Starting),
            "verification_pending" => Some(Self::VerificationPending),
            _ => None,
        }
    }
}

/// Outcome of [`CampaignManager::start_campaign_operation`]: the durable
/// operation id, the phase it reached, the canonical enrollment outcome (when
/// the campaign had recipients) and the operator message for a non-active
/// phase.
#[derive(Debug)]
pub struct CampaignStartReport {
    /// The durable start operation id (`sales_campaigns.start_operation_id`).
    /// Stable across every retry/resume of the same operation.
    pub operation_id: Uuid,
    pub phase: CampaignStartPhase,
    /// The canonical enrollment outcome; `None` when the campaign has no
    /// recipients (nothing was enrolled).
    pub outreach: Option<StartOutreachResponse>,
    /// Operator-readable explanation for a non-active phase (also persisted in
    /// `sales_campaigns.last_error`).
    pub message: Option<String>,
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

    /// Transition a draft/paused campaign to Active through a durable,
    /// resumable start operation, and materialize its recipients into
    /// canonical enrollments.
    ///
    /// # Durable start state machine
    ///
    /// 1. **Admission** ([`Self::admit_campaign_start`]): in one transaction
    ///    holding the tenant-scoped advisory xact lock
    ///    `pg_advisory_xact_lock(hashtext(tenant_id))`, the campaign row is
    ///    locked `FOR UPDATE`, the max-active limit counts ACTIVE campaigns
    ///    plus in-flight `'starting'` reservations, and the operation is
    ///    durably admitted: `start_state = 'starting'` with a stable
    ///    `start_operation_id`. The advisory lock makes count + reserve atomic,
    ///    so two concurrent starts with one remaining slot serialize and the
    ///    second is refused with [`SalesError::MaxCampaignsReached`].
    /// 2. **Materialization** ([`Self::enroll_campaign_recipients`]): one
    ///    compatibility sequence (keyed by
    ///    `sales_sequences.legacy_campaign_id`, so retries reuse it), one
    ///    contact + email contact point per recipient, and canonical
    ///    enrollments through [`crate::enrollments::start_outreach`]. Every
    ///    write is idempotent, so a retry duplicates nothing. A failure here
    ///    propagates with the campaign still `'starting'` — NOT active — and
    ///    the next call resumes the SAME operation id.
    /// 3. **Finalization** ([`Self::activate_campaign_operation`] /
    ///    [`Self::park_campaign_verification_pending`]): under the tenant lock,
    ///    the campaign becomes ACTIVE when at least one contact is eligible
    ///    (accepted now, or a live enrollment already exists for the campaign);
    ///    with zero eligible contacts it parks in `'verification_pending'` —
    ///    never active with no recipient that could actually be sent to.
    ///
    /// This is deliberately NOT one giant transaction: every materialization
    /// write is individually idempotent and the durable `'starting'` row is the
    /// operation's recovery point.
    ///
    /// # Per-recipient legal policy
    ///
    /// The start does NOT choose a batch-level autonomy policy. Each contact's
    /// current policy is resolved independently by `start_outreach` from the
    /// canonical store (fail-closed), so a campaign spanning several
    /// jurisdictions enrolls each recipient under its own policy instead of
    /// collapsing the batch to `UNKNOWN` and rejecting legitimate contacts as
    /// `stale_policy`.
    ///
    /// # Security (SA-13)
    ///
    /// Every state write is scoped by `tenant_id` and guarded by the expected
    /// operation id / status, so no request can mutate a campaign it does not
    /// own and no stale writer can clobber a newer operation.
    ///
    /// Callers that render the per-recipient outcome (accepted / rejected /
    /// rejection reasons) should use [`Self::start_campaign_operation`]; this
    /// method keeps the `Campaign` return type for existing callers.
    pub async fn start_campaign(&self, tenant_id: &str, id: Uuid) -> Result<Campaign, SalesError> {
        let (campaign, _report) = self.start_campaign_operation(tenant_id, id).await?;
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
        let (campaign, report) = self.start_campaign_operation(tenant_id, id).await?;
        Ok((campaign, report.outreach))
    }

    /// [`Self::start_campaign`], returning the full durable start-operation
    /// state: the operation id, its phase, the operator message and the
    /// canonical enrollment outcome.
    ///
    /// This is the route-facing entry point. A campaign that could not be
    /// activated (mid-materialization failure, or enrollment accepted zero
    /// contacts) is reported with its durable phase instead of a bare status,
    /// and a retry resumes the same `operation_id`.
    pub async fn start_campaign_operation(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<(Campaign, CampaignStartReport), SalesError> {
        // 1. Durable admission under the tenant lock (count + reserve).
        let admission = self.admit_campaign_start(tenant_id, id).await?;

        // 2. Normalized, de-duplicated legacy recipient list. Every address
        //    becomes a canonical contact whose gates the enrollment machinery
        //    evaluates. Empty means nothing to enroll — zero accepted, handled
        //    at finalization.
        let emails = self.campaign_recipient_emails(tenant_id, id).await?;

        // 3. Materialization + enrollment, outside the admission lock. A
        //    failure here leaves the durable 'starting' state, and the next
        //    call resumes the same operation.
        let outreach = if emails.is_empty() {
            None
        } else {
            Some(
                self.enroll_campaign_recipients(tenant_id, &admission.campaign, &emails)
                    .await?,
            )
        };

        let accepted = outreach.as_ref().map_or(0, |outcome| outcome.accepted);
        let live_enrollments = self
            .live_campaign_enrollment_count(tenant_id, admission.campaign.id)
            .await?;

        // 4. Finalize: ACTIVE only when at least one contact can actually be
        //    sent to (newly accepted, or already live from an earlier partial
        //    attempt). Zero eligible contacts parks in verification_pending.
        if accepted == 0 && live_enrollments == 0 {
            let message = self
                .park_campaign_verification_pending(
                    tenant_id,
                    id,
                    admission.operation_id,
                    emails.len(),
                    outreach.as_ref(),
                )
                .await?;
            let campaign = self
                .load_campaign(tenant_id, id)
                .await?
                .ok_or(SalesError::CampaignNotFound(id))?;
            tracing::warn!(
                tenant_id = %tenant_id,
                campaign_id = %id,
                operation_id = %admission.operation_id,
                recipients = emails.len(),
                "campaign start accepted zero contacts — campaign parked in \
                 verification_pending and is NOT active"
            );
            return Ok((
                campaign,
                CampaignStartReport {
                    operation_id: admission.operation_id,
                    phase: CampaignStartPhase::VerificationPending,
                    outreach,
                    message: Some(message),
                },
            ));
        }

        let campaign = self
            .activate_campaign_operation(tenant_id, id, admission.operation_id)
            .await?;

        match outreach {
            Some(ref outcome) => {
                tracing::info!(
                    tenant_id = %tenant_id,
                    campaign_id = %id,
                    operation_id = %admission.operation_id,
                    accepted = outcome.accepted,
                    rejected = outcome.rejected,
                    live_enrollments,
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
            None => {
                tracing::info!(
                    tenant_id = %tenant_id,
                    campaign_id = %id,
                    operation_id = %admission.operation_id,
                    live_enrollments,
                    "campaign start activated with no recipients to enroll"
                );
            }
        }

        Ok((
            campaign,
            CampaignStartReport {
                operation_id: admission.operation_id,
                phase: CampaignStartPhase::Active,
                outreach,
                message: None,
            },
        ))
    }

    /// Durable admission of a start operation, under the tenant-scoped advisory
    /// xact lock. Returns the campaign as read (status draft/paused) plus the
    /// operation id that every retry will reuse.
    async fn admit_campaign_start(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<StartAdmission, SalesError> {
        tokio::time::timeout(
            Duration::from_secs(30),
            self.admit_campaign_start_locked(tenant_id, id),
        )
        .await
        .map_err(|_| {
            SalesError::Database(
                "campaign start admission timed out — another start for this tenant is \
                 holding the tenant lock"
                    .into(),
            )
        })?
    }

    async fn admit_campaign_start_locked(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<StartAdmission, SalesError> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // Tenant-scoped advisory xact lock: serialize every start decision for
        // this tenant so the max-active count + reservation below cannot race.
        // A hash collision between tenants only over-serializes (correctness is
        // unaffected).
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        let row: Option<CampaignStartRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, \
                    created_at, start_state, start_operation_id \
             FROM sales_campaigns WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        let row = row.ok_or(SalesError::CampaignNotFound(id))?;

        if !matches!(row.status.as_str(), "draft" | "paused") {
            return Err(SalesError::InvalidInput(format!(
                "cannot start campaign in status {}",
                row.status
            )));
        }

        let durable_phase = match row.start_state.as_deref() {
            None => None,
            Some(raw) => match CampaignStartPhase::parse_durable(raw) {
                Some(phase) => Some(phase),
                None => {
                    return Err(SalesError::Internal(anyhow::anyhow!(
                        "campaign {id} has unknown start_state '{raw}'"
                    )))
                }
            },
        };
        // A pending phase implies a durable operation id (DB constraint); a
        // missing id is corruption, not a reason to mint a second operation.
        if durable_phase.is_some() && row.start_operation_id.is_none() {
            return Err(SalesError::Internal(anyhow::anyhow!(
                "campaign {id} is in start_state '{}' without a start_operation_id",
                row.start_state.as_deref().unwrap_or_default()
            )));
        }

        // Resume the SAME durable operation after a failure/zero-accept park;
        // only a fresh admission mints a new id and takes a new slot.
        let resuming = durable_phase.is_some();
        let operation_id = row.start_operation_id.unwrap_or_else(Uuid::new_v4);

        if !resuming {
            // Count ACTIVE campaigns plus in-flight 'starting' reservations
            // (this campaign is excluded: it holds no slot yet). Create-time
            // counting alone is bypassable — drafts are unlimited — so the
            // authoritative check is here, under the tenant lock.
            let reserved: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sales_campaigns \
                 WHERE tenant_id = $1 AND id <> $2 \
                   AND (status = 'active' OR start_state = 'starting')",
            )
            .bind(tenant_id)
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

            if reserved >= self.max_campaigns as i64 {
                // Nothing written: dropping the transaction rolls back.
                return Err(SalesError::MaxCampaignsReached(self.max_campaigns));
            }
        }

        let updated: Option<Option<Uuid>> = sqlx::query_scalar(
            "UPDATE sales_campaigns \
             SET start_state = 'starting', start_operation_id = $3, last_error = NULL \
             WHERE id = $1 AND tenant_id = $2 \
             RETURNING start_operation_id",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(operation_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        // The row is held FOR UPDATE, so the UPDATE must have hit it.
        let stored_operation_id = updated.flatten().ok_or_else(|| {
            SalesError::Internal(anyhow::anyhow!(
                "campaign {id} start admission did not persist its operation id"
            ))
        })?;

        let campaign = row.into_campaign()?;
        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(StartAdmission {
            campaign,
            operation_id: stored_operation_id,
        })
    }

    /// The normalized, de-duplicated legacy recipient list for a campaign.
    async fn campaign_recipient_emails(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
    ) -> Result<Vec<String>, SalesError> {
        let emails: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT LOWER(BTRIM(r.email)) FROM sales_campaign_recipients r \
             JOIN sales_campaigns c ON c.id = r.campaign_id \
             WHERE r.campaign_id = $1 AND c.tenant_id = $2 \
             ORDER BY 1",
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(emails
            .into_iter()
            .filter(|email| !email.is_empty())
            .collect())
    }

    /// Live (non-terminal) enrollments of the campaign's compatibility
    /// sequence. These are contacts that can still be sent to, so an
    /// already-enrolled re-start (e.g. after a pause) is a legitimate
    /// activation even when the enrollment command reports `accepted = 0`.
    async fn live_campaign_enrollment_count(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
    ) -> Result<i64, SalesError> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_enrollments e \
             JOIN sales_sequence_versions v ON v.id = e.sequence_version_id \
             JOIN sales_sequences s ON s.id = v.sequence_id \
             WHERE e.tenant_id = $1 AND s.tenant_id = $1 \
               AND s.legacy_campaign_id = $2 \
               AND e.state NOT IN ('completed', 'failed', 'suppressed')",
        )
        .bind(tenant_id)
        .bind(campaign_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))
    }

    /// Park a completed start whose enrollment accepted zero contacts in the
    /// durable `verification_pending` phase: the campaign is NOT activated and
    /// the operator-readable reason is persisted in `last_error`.
    async fn park_campaign_verification_pending(
        &self,
        tenant_id: &str,
        id: Uuid,
        operation_id: Uuid,
        recipients: usize,
        outreach: Option<&StartOutreachResponse>,
    ) -> Result<String, SalesError> {
        let rejection_detail = match outreach {
            Some(outcome) if !outcome.rejection_reasons.is_empty() => {
                format!("{:?}", outcome.rejection_reasons)
            }
            Some(_) => "no rejection reasons recorded".to_string(),
            None => "the campaign has no recipients".to_string(),
        };
        let message = format!(
            "start operation {operation_id} accepted 0 of {recipients} recipients — campaign \
             not activated (verification_pending); rejections: {rejection_detail}"
        );

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        let affected = sqlx::query(
            "UPDATE sales_campaigns \
             SET start_state = 'verification_pending', last_error = $4 \
             WHERE id = $1 AND tenant_id = $2 AND start_operation_id = $3 \
               AND status IN ('draft', 'paused')",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(operation_id)
        .bind(&message)
        .execute(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .rows_affected();

        if affected == 0 {
            return Err(SalesError::InvalidInput(
                "campaign start operation is no longer resumable (status or operation id \
                 changed concurrently)"
                    .into(),
            ));
        }

        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(message)
    }

    /// Activate a campaign whose start operation completed with at least one
    /// eligible contact. The operation-id guard makes this write idempotent and
    /// impossible for a superseded operation to perform.
    async fn activate_campaign_operation(
        &self,
        tenant_id: &str,
        id: Uuid,
        operation_id: Uuid,
    ) -> Result<Campaign, SalesError> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        let row: Option<CampaignRow> = sqlx::query_as(
            "UPDATE sales_campaigns \
             SET status = 'active', start_state = NULL, last_error = NULL \
             WHERE id = $1 AND tenant_id = $2 AND start_operation_id = $3 \
               AND status IN ('draft', 'paused') \
             RETURNING id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(operation_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let campaign = match row.and_then(|r| r.into_campaign().ok()) {
            Some(campaign) => campaign,
            None => {
                // A concurrent resume of the SAME operation already activated
                // it (we hold the tenant lock, so that commit is visible):
                // activation is idempotent, not an error.
                let already: Option<CampaignRow> = sqlx::query_as(
                    "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, \
                            clicked, created_at \
                     FROM sales_campaigns \
                     WHERE id = $1 AND tenant_id = $2 AND start_operation_id = $3 \
                       AND status = 'active'",
                )
                .bind(id)
                .bind(tenant_id)
                .bind(operation_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
                already
                    .and_then(|r| r.into_campaign().ok())
                    .ok_or_else(|| {
                        SalesError::InvalidInput(
                            "campaign start operation is no longer resumable (status or operation \
                         id changed concurrently)"
                                .into(),
                        )
                    })?
            }
        };

        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
        Ok(campaign)
    }

    /// Read one campaign for a tenant.
    async fn load_campaign(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<Campaign>, SalesError> {
        let row: Option<CampaignRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at \
             FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        row.map(|r| r.into_campaign()).transpose()
    }

    /// Enroll every materialized campaign recipient through the ONE canonical
    /// entry point, [`crate::enrollments::start_outreach`] — the same gates
    /// `/enrollments` uses (existence, email, suppression, legal policy,
    /// verification, duplicate enrollment). Chunked to the outreach command's
    /// per-call bound; the aggregate response reports the exact per-reason
    /// rejection counts.
    ///
    /// No batch-level `autonomy_policy_id` is sent: the enrollment command
    /// resolves the current policy independently for every contact.
    async fn enroll_campaign_recipients(
        &self,
        tenant_id: &str,
        campaign: &Campaign,
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
                autonomy_policy_id: None,
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
// Internal types for sqlx mapping and the start state machine
// ---------------------------------------------------------------------------

/// One admitted (or resumed) start operation.
struct StartAdmission {
    /// The campaign as read at admission (status still draft/paused).
    campaign: Campaign,
    /// Stable durable operation id, reused by every retry.
    operation_id: Uuid,
}

/// A campaign row including the durable start-operation columns
/// (`start_state`, `start_operation_id`).
#[derive(sqlx::FromRow)]
struct CampaignStartRow {
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
    start_state: Option<String>,
    start_operation_id: Option<Uuid>,
}

impl CampaignStartRow {
    fn into_campaign(self) -> Result<Campaign, SalesError> {
        CampaignRow {
            id: self.id,
            tenant_id: self.tenant_id,
            name: self.name,
            template_id: self.template_id,
            audience: self.audience,
            status: self.status,
            sent: self.sent,
            opened: self.opened,
            clicked: self.clicked,
            created_at: self.created_at,
        }
        .into_campaign()
    }
}

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
    /// canonical enrollments instead of sending. Activation requires at least
    /// one contact that can actually be sent to, so tests that want an ACTIVE
    /// campaign must seed a verified contact point and add the address as a
    /// recipient.
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
        // A campaign activates only when at least one recipient can actually
        // be sent to, so the fixture needs a verified contact point.
        let email = format!("lifecycle-{}@example.com", &tenant[..12]);
        seed_verified_point(mgr.db(), &tenant, &email).await;
        mgr.add_recipients(&tenant, c.id, vec![email])
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
        // Activation needs at least one sendable recipient.
        let email = format!("max-{}@example.com", &tenant[..12]);
        seed_verified_point(mgr.db(), &tenant, &email).await;
        mgr.add_recipients(&tenant, c.id, vec![email])
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

        // Both drafts need a sendable recipient to be admitted (an admission
        // that accepted zero contacts parks instead of consuming a slot).
        for (campaign, index) in [(&c1, 1), (&c2, 2)] {
            let email = format!("max-start-{index}-{}@example.com", &tenant[..12]);
            seed_verified_point(mgr.db(), &tenant, &email).await;
            mgr.add_recipients(&tenant, campaign.id, vec![email])
                .await
                .unwrap();
        }

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
        seed_verified_point_for_account(pool, tenant, email, None).await
    }

    /// [`seed_verified_point`] with an explicit account relation, so the
    /// per-contact policy resolution uses the account's country (a contact
    /// without an account resolves the fail-closed UNKNOWN jurisdiction).
    async fn seed_verified_point_for_account(
        pool: &PgPool,
        tenant: &str,
        email: &str,
        account_id: Option<Uuid>,
    ) -> Uuid {
        let contact_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) \
             VALUES ($1, $2, $3, 'Existing Contact')",
        )
        .bind(contact_id)
        .bind(tenant)
        .bind(account_id)
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

    /// Insert an account owned by `tenant` with `country` and return its id.
    async fn seed_account(pool: &PgPool, tenant: &str, country: &str) -> (Uuid, String) {
        let account_id = Uuid::new_v4();
        let domain = format!("{account_id}.example");
        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, country, country_confidence) \
             VALUES ($1, $2, 'Policy Test Co', $3, $4, 0.95)",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(&domain)
        .bind(country)
        .execute(pool)
        .await
        .unwrap();
        (account_id, domain)
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
    /// invented company) and its new point is `unknown`, not `valid`. The
    /// created point cannot pass the canonical verification gate, so the start
    /// accepts ZERO contacts and must NOT activate the campaign: the campaign
    /// parks in `verification_pending` with an operator-visible reason instead
    /// of advertising an active campaign whose only recipient was rejected.
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

        let (started, report) = mgr
            .start_campaign_operation(&tenant, campaign.id)
            .await
            .unwrap();
        assert_eq!(
            started.status,
            CampaignStatus::Draft,
            "zero accepted contacts must not activate the campaign"
        );
        assert_eq!(
            report.phase,
            CampaignStartPhase::VerificationPending,
            "the honest state is verification_pending, not active"
        );
        let outcome = report.outreach.expect("recipients exist");
        // The created point is `unknown`, so the canonical verification gate
        // rejects the enrollment — it is NEVER silently treated as valid.
        assert_eq!(outcome.accepted, 0);
        assert_eq!(outcome.rejected, 1);
        assert_eq!(
            outcome.rejection_reasons.get("unverified_contact"),
            Some(&1)
        );
        let message = report
            .message
            .expect("a parked start must carry an operator message");
        assert!(
            message.contains("verification_pending") && message.contains("unverified_contact"),
            "the operator message must name the state and the rejection: {message}"
        );

        // The durable state is persisted and operator-visible in the row.
        let (status, start_state, operation_id, last_error): (
            String,
            Option<String>,
            Option<Uuid>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT status, start_state, start_operation_id, last_error \
             FROM sales_campaigns WHERE id = $1",
        )
        .bind(campaign.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "draft");
        assert_eq!(start_state.as_deref(), Some("verification_pending"));
        assert_eq!(
            operation_id,
            Some(report.operation_id),
            "the durable operation id must be persisted"
        );
        assert!(last_error
            .expect("last_error is the operator-visible reason")
            .contains("verification_pending"));

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

    /// Live DB (canonical schema): the start does NOT resolve one batch-level
    /// policy. A recipient whose jurisdiction has no approved policy is not a
    /// batch refusal: the canonical store resolves that contact to the
    /// fail-closed `ApprovalRequired` verdict (policy id NULL) and the
    /// enrollment proceeds on that verdict — the send path still gates it. The
    /// campaign must NOT be rejected as `stale_policy` for a policy id the
    /// batch resolver invented.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn campaign_start_resolves_policy_per_contact_for_unlisted_jurisdiction() {
        let Some(pool) =
            canonical_test_pool("campaigns::tests::campaign_start_policy_refused").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-policy");
        let mgr = CampaignManager::new(10, pool.clone());

        // A jurisdiction with no policy row at all, carried by the recipient's
        // account so the per-contact resolver picks it up.
        let country = crate::test_db::ensure_no_policy_jurisdiction(&pool).await;
        let (account_id, domain) = seed_account(&pool, &tenant, &country).await;
        let email = format!("policy-{}@{domain}", &tenant[..12]);
        seed_verified_point_for_account(&pool, &tenant, &email, Some(account_id)).await;

        let campaign = mgr
            .create_campaign(tenant.clone(), "Policy".into(), "t".into(), "all".into())
            .await
            .unwrap();
        mgr.add_recipients(&tenant, campaign.id, vec![email])
            .await
            .unwrap();

        let (started, report) = mgr
            .start_campaign_operation(&tenant, campaign.id)
            .await
            .unwrap();
        assert_eq!(started.status, CampaignStatus::Active);
        assert_eq!(report.phase, CampaignStartPhase::Active);
        let outcome = report.outreach.expect("recipients exist");
        assert_eq!(
            outcome.accepted, 1,
            "ApprovalRequired is planned, not rejected: {:?}",
            outcome.rejection_reasons
        );
        assert_eq!(outcome.rejected, 0);
        assert!(
            !outcome.rejection_reasons.contains_key("stale_policy"),
            "an unlisted jurisdiction must never be mislabelled stale_policy"
        );
        assert!(
            !outcome.rejection_reasons.contains_key("legal_policy"),
            "no policy resolves to ApprovalRequired, which is not a prohibition"
        );

        cleanup_campaign_fixture(&pool, &tenant).await;
    }

    /// Live DB (canonical schema): two recipients in DIFFERENT jurisdictions
    /// each resolve their OWN current policy. Before the fix the start picked
    /// one policy id for the whole batch (UNKNOWN for a multi-country list),
    /// and every contact was then rejected as `stale_policy` even though its
    /// own policy allowed contact.
    #[tokio::test]
    async fn campaign_start_resolves_each_jurisdiction_separately() {
        let Some(pool) =
            canonical_test_pool("campaigns::tests::campaign_start_mixed_jurisdictions").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-mixed-juris");
        let mgr = CampaignManager::new(10, pool.clone());

        // Two distinct, approved, allowing jurisdictions (fresh unused codes).
        let (jurisdiction_a, _policy_a) =
            crate::test_db::insert_unique_jurisdiction_policy_returning_id(
                &pool,
                "allowed",
                "legitimate_interest",
            )
            .await;
        let (jurisdiction_b, _policy_b) =
            crate::test_db::insert_unique_jurisdiction_policy_returning_id(
                &pool,
                "allowed",
                "legitimate_interest",
            )
            .await;

        let (account_a, domain_a) = seed_account(&pool, &tenant, &jurisdiction_a).await;
        let (account_b, domain_b) = seed_account(&pool, &tenant, &jurisdiction_b).await;
        let email_a = format!("mixed-a-{}@{domain_a}", &tenant[..12]);
        let email_b = format!("mixed-b-{}@{domain_b}", &tenant[..12]);
        let contact_a =
            seed_verified_point_for_account(&pool, &tenant, &email_a, Some(account_a)).await;
        let contact_b =
            seed_verified_point_for_account(&pool, &tenant, &email_b, Some(account_b)).await;

        let campaign = mgr
            .create_campaign(
                tenant.clone(),
                "Mixed jurisdictions".into(),
                "t".into(),
                "all".into(),
            )
            .await
            .unwrap();
        mgr.add_recipients(&tenant, campaign.id, vec![email_a, email_b])
            .await
            .unwrap();

        let (started, report) = mgr
            .start_campaign_operation(&tenant, campaign.id)
            .await
            .unwrap();
        assert_eq!(started.status, CampaignStatus::Active);
        let outcome = report.outreach.expect("recipients exist");
        assert_eq!(
            outcome.accepted, 2,
            "both jurisdictions must enroll under their own policy: {:?}",
            outcome.rejection_reasons
        );
        assert_eq!(outcome.rejected, 0);
        assert!(
            !outcome.rejection_reasons.contains_key("stale_policy"),
            "a mixed-jurisdiction batch must not collapse to stale_policy: {:?}",
            outcome.rejection_reasons
        );

        // Each enrollment exists exactly once, under the campaign's sequence.
        let enrolled: Vec<Uuid> = sqlx::query_scalar(
            "SELECT e.contact_id FROM sales_enrollments e \
             JOIN sales_sequence_versions v ON v.id = e.sequence_version_id \
             JOIN sales_sequences s ON s.id = v.sequence_id \
             WHERE e.tenant_id = $1 AND s.legacy_campaign_id = $2 ORDER BY e.contact_id",
        )
        .bind(&tenant)
        .bind(campaign.id)
        .fetch_all(&pool)
        .await
        .unwrap();
        let mut expected = vec![contact_a, contact_b];
        expected.sort_unstable();
        assert_eq!(enrolled, expected);

        cleanup_campaign_fixture(&pool, &tenant).await;
    }

    /// Live DB (canonical schema): a failure in the middle of materialization
    /// leaves the campaign in the durable `starting` phase (NOT active), and a
    /// retry RESUMES the same operation id without duplicating the sequence,
    /// contacts, enrollments or queued actions.
    #[tokio::test]
    async fn failed_start_is_resumable_and_never_duplicates() {
        let Some(pool) = canonical_test_pool("campaigns::tests::failed_start_is_resumable").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-resume");
        let mgr = CampaignManager::new(10, pool.clone());
        let email = format!("resume-{}@example.com", &tenant[..12]);
        seed_verified_point(&pool, &tenant, &email).await;

        let campaign = mgr
            .create_campaign(tenant.clone(), "Resumable".into(), "t".into(), "all".into())
            .await
            .unwrap();
        mgr.add_recipients(&tenant, campaign.id, vec![email])
            .await
            .unwrap();

        // Inject a failure into the FIRST materialization write (the
        // compatibility sequence), AFTER the durable admission has committed.
        // The trigger fires for no other test's tenant (every tenant id is
        // unique per run).
        let function_name = format!("fail_sequences_{}", tenant.replace('-', "_"));
        let trigger_name = format!("{function_name}_trg");
        sqlx::query(&format!(
            "CREATE OR REPLACE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'injected mid-materialization failure'; END $$"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "CREATE TRIGGER {trigger_name} BEFORE INSERT ON sales_sequences \
             FOR EACH ROW WHEN (NEW.tenant_id = '{tenant}') \
             EXECUTE FUNCTION {function_name}()"
        ))
        .execute(&pool)
        .await
        .unwrap();

        let failed = mgr.start_campaign(&tenant, campaign.id).await;
        assert!(
            matches!(failed, Err(SalesError::Database(_))),
            "the injected failure must surface: {failed:?}"
        );

        let (status, start_state, operation_id): (String, Option<String>, Option<Uuid>) =
            sqlx::query_as(
                "SELECT status, start_state, start_operation_id \
                 FROM sales_campaigns WHERE id = $1",
            )
            .bind(campaign.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "draft", "a failed start must not activate");
        assert_eq!(
            start_state.as_deref(),
            Some("starting"),
            "the durable starting phase is the recovery point"
        );
        let operation_id = operation_id.expect("the operation id is durable");
        assert_eq!(
            scalar_count(
                &pool,
                "SELECT COUNT(*) FROM sales_enrollments WHERE tenant_id = $1",
                &tenant
            )
            .await,
            0,
            "the failed materialization enrolled nobody"
        );
        assert_eq!(
            scalar_count(
                &pool,
                "SELECT COUNT(*) FROM sales_sequences WHERE tenant_id = $1",
                &tenant
            )
            .await,
            0,
            "the failed sequence materialization wrote nothing"
        );

        // Remove the injected failure and retry: the SAME operation resumes.
        sqlx::query(&format!("DROP TRIGGER {trigger_name} ON sales_sequences"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(&format!("DROP FUNCTION {function_name}()"))
            .execute(&pool)
            .await
            .unwrap();

        let (started, report) = mgr
            .start_campaign_operation(&tenant, campaign.id)
            .await
            .unwrap();
        assert_eq!(started.status, CampaignStatus::Active);
        assert_eq!(report.phase, CampaignStartPhase::Active);
        assert_eq!(
            report.operation_id, operation_id,
            "the retry must resume the SAME durable operation id"
        );
        let outcome = report.outreach.expect("recipients exist");
        assert_eq!(outcome.accepted, 1);
        assert_eq!(outcome.rejected, 0);

        // No duplicate sequence/enrollment/action from the resume.
        let sequences: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_sequences \
             WHERE tenant_id = $1 AND legacy_campaign_id = $2",
        )
        .bind(&tenant)
        .bind(campaign.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sequences, 1, "the compatibility sequence is reused");
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
                "SELECT COUNT(*) FROM sales_actions WHERE tenant_id = $1",
                &tenant
            )
            .await,
            1,
            "exactly one queued send action after the resume"
        );
        let start_state: Option<String> =
            sqlx::query_scalar("SELECT start_state FROM sales_campaigns WHERE id = $1")
                .bind(campaign.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(start_state.is_none(), "activation clears the pending phase");
        let last_error: Option<String> =
            sqlx::query_scalar("SELECT last_error FROM sales_campaigns WHERE id = $1")
                .bind(campaign.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(last_error.is_none(), "activation clears the operator error");

        cleanup_campaign_fixture(&pool, &tenant).await;
    }

    /// Live DB (canonical schema): two concurrent starts with exactly ONE
    /// remaining active slot must activate exactly one campaign. The
    /// tenant-scoped advisory xact lock serializes the count + reservation, and
    /// an in-flight `'starting'` row counts as a taken slot.
    #[tokio::test]
    async fn concurrent_starts_with_one_slot_activate_exactly_one() {
        let Some(pool) = canonical_test_pool("campaigns::tests::concurrent_starts_one_slot").await
        else {
            return;
        };
        let tenant = unique_test_tenant("campaign-race");
        let mgr = CampaignManager::new(1, pool.clone());

        let mut campaigns = Vec::new();
        for index in 0..2 {
            let campaign = mgr
                .create_campaign(
                    tenant.clone(),
                    format!("Race {index}"),
                    "t".into(),
                    "a".into(),
                )
                .await
                .unwrap();
            let email = format!("race-{index}-{}@example.com", &tenant[..12]);
            seed_verified_point(&pool, &tenant, &email).await;
            mgr.add_recipients(&tenant, campaign.id, vec![email])
                .await
                .unwrap();
            campaigns.push(campaign);
        }

        let (first, second) = tokio::join!(
            mgr.start_campaign(&tenant, campaigns[0].id),
            mgr.start_campaign(&tenant, campaigns[1].id),
        );

        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_campaigns \
             WHERE tenant_id = $1 AND status = 'active'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            active, 1,
            "exactly one of two concurrent starts may take the last slot"
        );

        let outcomes = [first, second];
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
            1,
            "exactly one start may succeed: {outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .any(|outcome| matches!(outcome, Err(SalesError::MaxCampaignsReached(1)))),
            "the loser must be refused with MaxCampaignsReached: {outcomes:?}"
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
