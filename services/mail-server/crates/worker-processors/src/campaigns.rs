//! Campaign send pipeline (`/v1/campaigns` sends actually go out here).
//!
//! # Why this module exists
//!
//! Dogfood finding DF-3: campaigns could be created, scheduled and "sent" via
//! the API, but NOTHING consumed them — no worker read `campaigns.scheduled_at`
//! or drained `campaign_jobs`, so a scheduled campaign never sent and the
//! resend endpoint's `campaign_jobs` row sat `queued` forever. This executor is
//! the missing consumer, ticked by the worker binary next to the automation
//! executor.
//!
//! # The pipeline
//!
//! 1. **Due scheduled campaigns** — `status = 'scheduled' AND scheduled_at <=
//!    NOW()` is claimed with `FOR UPDATE SKIP LOCKED`, the audience is expanded
//!    from `list_ids` / `exclude_list_ids` into `campaign_recipients` and the
//!    campaign flips to `sending` (the drain phase's gate).
//! 2. **Resend jobs** — `campaign_jobs` rows with `job_type = 'resend'` are
//!    claimed the same way: failed recipients are requeued (`failed` →
//!    `queued`), the campaign returns to `sending`, and the job completes.
//!    Suppressed recipients are NEVER retried (compliance), and already-sent
//!    recipients are never re-sent.
//! 3. **Drain** — a bounded batch of `campaign_recipients` rows whose campaign
//!    is `sending`/`resending` is claimed under a lease (`FOR UPDATE SKIP
//!    LOCKED` + stale-lease recovery). Per recipient the EXACT automations
//!    send ladder runs: canonical suppression gate +
//!    [`SendAdmissionService`](billing_service::send_admission::SendAdmissionService)
//!    (the ONE admission gate, explicit `marketing` category, rollback on
//!    failure), per-contact template render, one transaction writing `messages`
//!    (`status 'queued'`, idempotency key `campaign:{campaign_id}:{contact_id}`)
//!    plus `email_queue` (with `campaign_id`/`contact_id` back-references so
//!    downstream events carry the campaign). A poison recipient is recorded
//!    `failed` with its error — it never blocks the batch.
//! 4. **Converge** — a `sending`/`resending` campaign with no in-flight or
//!    queued recipient rows left is finalized: `sent` when nothing failed,
//!    `partial` otherwise, and `sent_count` is set from the real per-recipient
//!    outcomes.
//!
//! # Pause / resume
//!
//! Every claim joins `campaigns.status IN ('sending', 'resending')`: pausing a
//! campaign (`paused`) stops the drain mid-flight — claimed rows stall under
//! their lease until recovery re-claims them after resume, and no new rows are
//! claimed. Resume flips the campaign back to `sending` (or `scheduled` when
//! its `scheduled_at` is still in the future) and the pipeline continues where
//! it stopped. The per-recipient idempotency key makes the recovery exactly-once.
//!
//! # Tenant isolation
//!
//! Every statement binds the `tenant_id` read from the claimed row itself;
//! lists, contacts, templates, suppression checks and the enqueue are all
//! tenant-scoped. There is no cross-tenant read in this module.

use std::collections::HashMap;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use analytics::send_time_optimizer::SendTimeOptimizer;
use apexmail_lib::email_headers::message_category;
use billing_service::send_admission::{
    AdmissionMeter, SendAdmissionError, SendAdmissionRequest, SendAdmissionService,
};

use crate::automations::{fetch_template, TemplateContent};

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Campaign claims (scheduled starts + resend jobs) processed per tick.
pub const DEFAULT_BATCH_SIZE: i64 = 25;

/// Recipient rows drained per tick (bounded work; the rest waits for the next
/// tick — the email processor delivers concurrently).
pub const DRAIN_BATCH_SIZE: i64 = 100;

/// Lease held while one claimed recipient row is being processed. A crashed
/// worker's rows become reclaimable after this window; the per-recipient
/// idempotency key makes the reclaim exactly-once.
const RECIPIENT_LEASE_SECS: i64 = 300;

/// Retryable-failure cap per recipient row: a row that failed this many times
/// at the enqueue stage is parked `failed` for a resend to pick up instead of
/// cycling forever.
const MAX_RECIPIENT_ATTEMPTS: i32 = 5;

/// Bound on the recorded per-recipient error text.
const MAX_ERROR_LEN: usize = 512;

// ---------------------------------------------------------------------------
// Errors / report
// ---------------------------------------------------------------------------

/// Errors surfaced by the campaign executor. Quota and suppression outcomes
/// are per-recipient states, NOT errors; only infrastructure failures are.
#[derive(Debug, thiserror::Error)]
pub enum CampaignError {
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for CampaignError {
    fn from(error: sqlx::Error) -> Self {
        CampaignError::Database(error.to_string())
    }
}

/// What one tick did, for the worker's structured log.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
    pub campaigns_started: u64,
    pub jobs_completed: u64,
    pub jobs_deferred: u64,
    pub recipients_sent: u64,
    pub recipients_failed: u64,
    pub recipients_suppressed: u64,
    pub recipients_deferred: u64,
    pub campaigns_completed: u64,
}

impl TickReport {
    fn merge(&mut self, other: TickReport) {
        self.campaigns_started += other.campaigns_started;
        self.jobs_completed += other.jobs_completed;
        self.jobs_deferred += other.jobs_deferred;
        self.recipients_sent += other.recipients_sent;
        self.recipients_failed += other.recipients_failed;
        self.recipients_suppressed += other.recipients_suppressed;
        self.recipients_deferred += other.recipients_deferred;
        self.campaigns_completed += other.campaigns_completed;
    }
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// The campaign consumer. Construct once (worker binary), tick forever.
pub struct CampaignExecutor {
    db: PgPool,
    admission: SendAdmissionService,
    worker_id: String,
    batch_size: i64,
    drain_batch_size: i64,
    /// Send-time optimization engine (Pro+ feature). `None` (test harnesses,
    /// optimizers disabled) sends immediately when a campaign asks for STO;
    /// the production worker binary always injects it.
    send_time: Option<SendTimeOptimizer>,
}

/// One claimed scheduled campaign, with its stored audience definition.
struct DueCampaign {
    id: Uuid,
    tenant_id: String,
    list_ids: Vec<Uuid>,
    exclude_list_ids: Vec<Uuid>,
    segment_id: Option<Uuid>,
    ab_config: Option<serde_json::Value>,
}

/// One claimed recipient row plus the identity needed to send it.
struct ClaimedRecipient {
    id: Uuid,
    tenant_id: String,
    campaign_id: Uuid,
    contact_id: Uuid,
    email: String,
    /// A/B phase ('test' | 'winner' | 'holdout' | NULL) and arm index.
    phase: Option<String>,
    arm_index: Option<i32>,
}

/// One A/B arm's content: a template plus an optional subject override.
struct ArmContent {
    subject: Option<String>,
    template: Option<TemplateContent>,
}

/// Per-campaign send context resolved once per drain batch. Carries every
/// documented content/settings field so the ladder can render the full
/// contract: template OR inline html/text, global variables, preview text,
/// UTM parameters, display name, reply-to, per-campaign tracking toggles,
/// throttling and the dedicated-IP pool.
struct CampaignSendContext {
    from_email: String,
    from_name: Option<String>,
    reply_to: Option<String>,
    subject: String,
    preview_text: Option<String>,
    html: Option<String>,
    text: Option<String>,
    variables: serde_json::Value,
    utm_params: serde_json::Value,
    track_opens: bool,
    track_clicks: bool,
    ip_pool: Option<String>,
    throttle_rate: Option<i64>,
    /// `settings.sendTimeOptimization`: schedule each recipient at their
    /// optimal engagement window (documented Pro+ contract).
    send_time_optimization: bool,
    /// `settings.timezone` (IANA) as a fixed UTC offset for the STO windows;
    /// `None` falls back to the tenant's own offset.
    sto_offset_minutes: Option<i32>,
    /// The campaign-level template (None for inline-html campaigns).
    template: Option<TemplateContent>,
    /// Per-arm content for A/B campaigns, keyed by arm_index.
    arms: std::collections::HashMap<i32, ArmContent>,
}

impl CampaignSendContext {
    /// The content (template + subject override) this recipient sends with:
    /// its own arm for test/winner phases, the campaign default otherwise.
    fn content_for(
        &self,
        recipient: &ClaimedRecipient,
    ) -> (Option<&TemplateContent>, Option<&str>, Option<&str>) {
        if let (Some(phase), Some(arm_index)) = (recipient.phase.as_deref(), recipient.arm_index) {
            if phase == "test" || phase == "winner" {
                if let Some(arm) = self.arms.get(&arm_index) {
                    return (arm.template.as_ref(), arm.subject.as_deref(), None);
                }
            }
        }
        (self.template.as_ref(), None, None)
    }

    /// Whether this recipient has renderable content: its arm's template,
    /// the campaign template, or the campaign's inline html. A/B campaigns
    /// always resolve through arm templates.
    fn has_content_for(&self, recipient: &ClaimedRecipient) -> bool {
        let (template, _, _) = self.content_for(recipient);
        template.is_some() || (self.template.is_none() && self.html.is_some())
    }
}

impl CampaignExecutor {
    pub fn new(db: PgPool, admission: SendAdmissionService, worker_id: impl Into<String>) -> Self {
        Self {
            db,
            admission,
            worker_id: worker_id.into(),
            batch_size: DEFAULT_BATCH_SIZE,
            drain_batch_size: DRAIN_BATCH_SIZE,
            send_time: None,
        }
    }

    /// Attach the send-time optimization engine (`settings.sendTimeOptimization`).
    pub fn with_send_time_optimizer(mut self, optimizer: SendTimeOptimizer) -> Self {
        self.send_time = Some(optimizer);
        self
    }

    /// Override the per-tick claim bounds (tests).
    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    pub fn with_drain_batch_size(mut self, drain_batch_size: i64) -> Self {
        self.drain_batch_size = drain_batch_size.max(1);
        self
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// One bounded pass: start due scheduled campaigns, process resend jobs,
    /// drain a batch of recipients, then finalize finished campaigns.
    pub async fn tick(&self) -> Result<TickReport, CampaignError> {
        let mut report = TickReport::default();

        report.merge(self.start_due_scheduled_campaigns().await?);
        report.merge(self.split_pending_ab_campaigns().await?);
        report.merge(self.evaluate_ab_tests().await?);
        report.merge(self.process_resend_jobs().await?);
        report.merge(self.drain_queued_recipients().await?);
        report.merge(self.finalize_finished_campaigns().await?);

        Ok(report)
    }

    // -- Phase 1: due scheduled campaigns ---------------------------------

    /// Claim due `scheduled` campaigns (`FOR UPDATE SKIP LOCKED`), expand
    /// their audience and leave them `sending` for the drain phase. A
    /// campaign with zero recipients stays `sending` untouched: the finalize
    /// phase never touches campaigns without recipient rows, and the
    /// zero-recipient case is the API's responsibility to report honestly at
    /// send time.
    async fn start_due_scheduled_campaigns(&self) -> Result<TickReport, CampaignError> {
        let due: Vec<DueCampaign> = sqlx::query_as(
            "UPDATE campaigns \
             SET status = 'sending', updated_at = NOW() \
             WHERE id IN ( \
                 SELECT id FROM campaigns \
                 WHERE status = 'scheduled' AND scheduled_at <= NOW() \
                 ORDER BY scheduled_at, id \
                 LIMIT $1 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING id, tenant_id, \
                       COALESCE(list_ids, '[]'::jsonb), \
                       COALESCE(exclude_list_ids, '[]'::jsonb), \
                       segment_id, \
                       ab_config",
        )
        .bind(self.batch_size)
        .fetch_all(&self.db)
        .await?
        .into_iter()
        .map(
            |row: (
                Uuid,
                String,
                serde_json::Value,
                serde_json::Value,
                Option<Uuid>,
                Option<serde_json::Value>,
            )| DueCampaign {
                id: row.0,
                tenant_id: row.1,
                list_ids: uuid_array(&row.2),
                exclude_list_ids: uuid_array(&row.3),
                segment_id: row.4,
                ab_config: row.5,
            },
        )
        .collect();

        let mut report = TickReport::default();
        for campaign in &due {
            let inserted = self.expand_audience(campaign).await?;
            if campaign.ab_config.is_some() {
                self.split_ab_recipients(campaign.id, campaign.ab_config.as_ref())
                    .await?;
            }
            enqueue_campaign_event_webhooks(
                &self.db,
                &campaign.tenant_id,
                "campaign.started",
                serde_json::json!({
                    "id": format!("evt_{}", Uuid::new_v4().simple()),
                    "type": "campaign.started",
                    "tenantId": campaign.tenant_id,
                    "timestamp": Utc::now().to_rfc3339(),
                    "data": {
                        "campaign_id": campaign.id.to_string(),
                        "recipients": inserted,
                        "ab_test": campaign.ab_config.is_some(),
                    },
                }),
            )
            .await;
            tracing::info!(
                campaign_id = %campaign.id,
                tenant_id = %campaign.tenant_id,
                recipients = inserted,
                "scheduled campaign claimed; audience expanded"
            );
            report.campaigns_started += 1;
        }
        Ok(report)
    }

    /// Assign the A/B phases for a campaign whose recipients are still
    /// un-phased. The assignment is the shared deterministic contract
    /// (`apexmail_lib::ab_testing::AB_SPLIT_SQL`): a hash of
    /// `(campaign_id, contact_id)` picks the `test` sample of
    /// `ab_config.testPercentage` and its arm, so a replay/resend of the
    /// same audience assigns the same arm to the same contact regardless of
    /// row order or audience growth; the remainder becomes `holdout` and
    /// waits for the winner. `phase IS NULL` scoping makes re-runs no-ops.
    async fn split_ab_recipients(
        &self,
        campaign_id: Uuid,
        ab_config: Option<&serde_json::Value>,
    ) -> Result<u64, CampaignError> {
        let Some(config) = ab_config else {
            return Ok(0);
        };
        let test_percentage = config
            .get("testPercentage")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.2)
            .clamp(0.1, 0.5);
        let arm_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM campaign_ab_arms WHERE campaign_id = $1")
                .bind(campaign_id)
                .fetch_one(&self.db)
                .await?;
        if arm_count < 2 {
            return Ok(0);
        }

        let split = sqlx::query(apexmail_lib::ab_testing::AB_SPLIT_SQL)
            .bind(campaign_id)
            .bind(test_percentage)
            .bind(arm_count)
            .execute(&self.db)
            .await?;

        if split.rows_affected() > 0 {
            // The test window opens when the split lands.
            sqlx::query("UPDATE campaign_ab_arms SET updated_at = NOW() WHERE campaign_id = $1")
                .bind(campaign_id)
                .execute(&self.db)
                .await?;
        }
        Ok(split.rows_affected())
    }

    /// Record per-arm trials/successes from the events stream and, once the
    /// test window has elapsed with every test recipient drained, evaluate
    /// the shared winner rule (`apexmail_lib::ab_testing::decide_winner`:
    /// per-arm minimum sample + two-proportion z-test at the two-sided 95%
    /// level). A declared winner is promoted onto the holdout recipients; a
    /// refusal leaves the holdout held and logs the named reason (the
    /// experiments API surfaces the same reason and offers the audited
    /// manual declaration). Idempotent: the promotion touches only
    /// `phase = 'holdout'` rows, and a campaign whose ab_config already
    /// carries `winnerArm` is skipped.
    async fn evaluate_ab_tests(&self) -> Result<TickReport, CampaignError> {
        let candidates: Vec<(Uuid, String, serde_json::Value)> = sqlx::query_as(
            "SELECT id, tenant_id, ab_config FROM campaigns \
             WHERE status IN ('sending', 'resending') \
               AND ab_config IS NOT NULL \
               AND ab_config->>'winnerArm' IS NULL \
               AND EXISTS ( \
                   SELECT 1 FROM campaign_recipients cr \
                   WHERE cr.campaign_id = campaigns.id AND cr.phase = 'holdout' \
               ) \
             LIMIT $1",
        )
        .bind(self.batch_size)
        .fetch_all(&self.db)
        .await?;

        let mut report = TickReport::default();
        for (campaign_id, tenant_id, config) in candidates {
            let metric_event = match config.get("metric").and_then(|v| v.as_str()) {
                Some("click") => "clicked",
                _ => "opened",
            };
            let wait_minutes = config
                .get("waitMinutes")
                .and_then(|v| v.as_i64())
                .unwrap_or(60)
                .clamp(5, 1440);

            // Refresh trials/successes for every arm from the events stream
            // (shared SQL; the API reads the same numbers read-only).
            sqlx::query(apexmail_lib::ab_testing::AB_OUTCOMES_REFRESH_SQL)
                .bind(campaign_id)
                .bind(metric_event)
                .execute(&self.db)
                .await?;

            // The test phase must be fully drained, and the window must have
            // elapsed since the split.
            let test_in_flight: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM campaign_recipients \
                 WHERE campaign_id = $1 AND phase = 'test' AND status IN ('queued', 'sending')",
            )
            .bind(campaign_id)
            .fetch_one(&self.db)
            .await?;
            if test_in_flight > 0 {
                continue;
            }
            let window_open: bool = sqlx::query_scalar(
                "SELECT NOW() >= (SELECT MIN(updated_at) FROM campaign_ab_arms WHERE campaign_id = $1) \
                        + make_interval(mins => $2::int)",
            )
            .bind(campaign_id)
            .bind(wait_minutes)
            .fetch_one(&self.db)
            .await?;
            if !window_open {
                continue;
            }

            // The documented, guarded rule — refused below the minimum
            // per-arm sample or without a significant leader; the holdout
            // then keeps waiting (the API surfaces the reason).
            let outcomes: Vec<(i32, i64, i64)> =
                sqlx::query_as(apexmail_lib::ab_testing::AB_OUTCOMES_SELECT_SQL)
                    .bind(campaign_id)
                    .bind(metric_event)
                    .fetch_all(&self.db)
                    .await?;
            let arms: Vec<apexmail_lib::ab_testing::ArmOutcome> = outcomes
                .into_iter()
                .map(
                    |(arm_index, trials, successes)| apexmail_lib::ab_testing::ArmOutcome {
                        arm_index,
                        trials,
                        successes,
                    },
                )
                .collect();
            let verdict = apexmail_lib::ab_testing::decide_winner(&arms);
            let (winner, winner_z) = match verdict {
                apexmail_lib::ab_testing::AbVerdict::Winner { arm_index, z, .. } => (arm_index, z),
                apexmail_lib::ab_testing::AbVerdict::Refused { code, reason } => {
                    tracing::info!(
                        campaign_id = %campaign_id,
                        reason_code = code,
                        reason = %reason,
                        "A/B winner refused; holdout stays held until a manual declaration"
                    );
                    continue;
                }
            };

            let promoted = sqlx::query(
                "UPDATE campaign_recipients \
                 SET phase = 'winner', arm_index = $2, updated_at = NOW() \
                 WHERE campaign_id = $1 AND phase = 'holdout'",
            )
            .bind(campaign_id)
            .bind(winner)
            .execute(&self.db)
            .await?
            .rows_affected();

            // The decision is persisted with its provenance: which rule ran
            // (auto), on which metric, with which z — so the results API and
            // the audit trail can explain the promotion after the facts.
            sqlx::query(
                "UPDATE campaigns \
                 SET ab_config = ab_config || jsonb_build_object( \
                         'winnerArm', $2::int, \
                         'winnerSource', 'auto', \
                         'winnerMetric', $3::text, \
                         'winnerZ', $4::float8, \
                         'winnerAt', $5::text \
                     ), \
                     updated_at = NOW() \
                 WHERE id = $1",
            )
            .bind(campaign_id)
            .bind(winner)
            .bind(metric_event)
            .bind(winner_z)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.db)
            .await?;

            enqueue_campaign_event_webhooks(
                &self.db,
                &tenant_id,
                "campaign.ab_winner_selected",
                serde_json::json!({
                    "id": format!("evt_{}", Uuid::new_v4().simple()),
                    "type": "campaign.ab_winner_selected",
                    "tenantId": tenant_id,
                    "timestamp": Utc::now().to_rfc3339(),
                    "data": {
                        "campaign_id": campaign_id.to_string(),
                        "winner_arm": winner,
                        "metric": metric_event,
                        "z": winner_z,
                        "rule": "two_proportion_z_95",
                        "source": "auto",
                        "holdout_promoted": promoted,
                    },
                }),
            )
            .await;
            tracing::info!(
                campaign_id = %campaign_id,
                winner_arm = winner,
                winner_z,
                holdout_promoted = promoted,
                "A/B test concluded; winner promoted onto the holdout"
            );
            report.campaigns_started += 1;
        }
        Ok(report)
    }

    /// Assign A/B phases for any campaign whose recipients are still
    /// un-phased (the API's synchronous send expands without splitting; the
    /// scheduled path splits at claim). Bounded per tick.
    async fn split_pending_ab_campaigns(&self) -> Result<TickReport, CampaignError> {
        let pending: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
            "SELECT id, ab_config FROM campaigns \
             WHERE status IN ('sending', 'resending') \
               AND ab_config IS NOT NULL \
               AND ab_config->>'winnerArm' IS NULL \
               AND EXISTS ( \
                   SELECT 1 FROM campaign_recipients cr \
                   WHERE cr.campaign_id = campaigns.id AND cr.phase IS NULL \
               ) \
             LIMIT $1",
        )
        .bind(self.batch_size)
        .fetch_all(&self.db)
        .await?;
        for (campaign_id, config) in &pending {
            self.split_ab_recipients(*campaign_id, Some(config)).await?;
        }
        Ok(TickReport::default())
    }

    /// Insert the campaign's audience (subscribed contacts on `list_ids`,
    /// minus anyone on any `exclude_list_ids`) as `queued` recipient rows.
    /// Existing rows are never duplicated or downgraded (resends rely on the
    /// per-contact status machine surviving re-expansion).
    async fn expand_audience(&self, campaign: &DueCampaign) -> Result<u64, CampaignError> {
        // The audience is the union of the campaign's lists and (when a
        // segment is referenced) the segment's lists, matched by the
        // segment's tag/status rules, minus the union of both exclude sets.
        let mut include = campaign.list_ids.clone();
        let mut exclude = campaign.exclude_list_ids.clone();
        let mut statuses: Vec<String> = vec!["active".into(), "subscribed".into()];
        let mut tags_all: Option<Vec<String>> = None;
        let mut tags_any: Option<Vec<String>> = None;

        if let Some(segment_id) = campaign.segment_id {
            let segment: Option<(serde_json::Value, serde_json::Value, serde_json::Value)> =
                sqlx::query_as(
                    "SELECT COALESCE(list_ids, '[]'::jsonb), \
                            COALESCE(exclude_list_ids, '[]'::jsonb), \
                            COALESCE(match, '{}'::jsonb) \
                     FROM segments WHERE id = $1 AND tenant_id = $2",
                )
                .bind(segment_id)
                .bind(&campaign.tenant_id)
                .fetch_optional(&self.db)
                .await?;
            if let Some((seg_lists, seg_excludes, match_rules)) = segment {
                for id in uuid_array(&seg_lists) {
                    if !include.contains(&id) {
                        include.push(id);
                    }
                }
                for id in uuid_array(&seg_excludes) {
                    if !exclude.contains(&id) {
                        exclude.push(id);
                    }
                }
                if let Some(list) = match_rules.get("statuses").and_then(|v| v.as_array()) {
                    let parsed: Vec<String> = list
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                    if !parsed.is_empty() {
                        statuses = parsed;
                    }
                }
                tags_all = match_rules
                    .get("tags_all")
                    .and_then(|v| v.as_array())
                    .map(|list| {
                        list.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .filter(|v: &Vec<String>| !v.is_empty());
                tags_any = match_rules
                    .get("tags_any")
                    .and_then(|v| v.as_array())
                    .map(|list| {
                        list.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .filter(|v: &Vec<String>| !v.is_empty());
            }
        }

        // An EMPTY include set with no segment match rules is an empty
        // audience — never "every contact". (The cardinality escape in the
        // SQL below only ever selects when tag/status rules constrain the
        // audience, i.e. a tag-targeted segment with no lists.)
        if include.is_empty() && tags_all.is_none() && tags_any.is_none() {
            return Ok(0);
        }

        let result = sqlx::query(
            "INSERT INTO campaign_recipients (tenant_id, campaign_id, contact_id, email, status) \
             SELECT $1, $2, c.id, c.email, 'queued' \
             FROM contacts c \
             WHERE c.tenant_id = $1 \
               AND c.status = ANY($5) \
               AND ($6::text[] IS NULL OR c.tags ?& $6) \
               AND ($7::text[] IS NULL OR c.tags ?| $7) \
               AND ( \
                   cardinality($3::uuid[]) = 0 \
                   OR EXISTS ( \
                       SELECT 1 FROM list_subscribers ls \
                       WHERE ls.contact_id = c.id AND ls.status = 'active' \
                         AND ls.list_id = ANY($3) \
                   ) \
               ) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM list_subscribers ls \
                   WHERE ls.contact_id = c.id AND ls.list_id = ANY($4) \
               ) \
             ON CONFLICT (campaign_id, contact_id) DO NOTHING",
        )
        .bind(&campaign.tenant_id)
        .bind(campaign.id)
        .bind(&include)
        .bind(&exclude)
        .bind(&statuses)
        .bind(&tags_all)
        .bind(&tags_any)
        .execute(&self.db)
        .await?;
        Ok(result.rows_affected())
    }

    // -- Phase 2: resend jobs ---------------------------------------------

    async fn process_resend_jobs(&self) -> Result<TickReport, CampaignError> {
        let jobs: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
            "UPDATE campaign_jobs \
             SET status = 'processing', started_at = NOW() \
             WHERE id IN ( \
                 SELECT id FROM campaign_jobs \
                 WHERE job_type = 'resend' AND status IN ('queued', 'pending') \
                 ORDER BY created_at, id \
                 LIMIT $1 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING id, tenant_id, campaign_id",
        )
        .bind(self.batch_size)
        .fetch_all(&self.db)
        .await?;

        let mut report = TickReport::default();
        for (job_id, tenant_id, campaign_id) in jobs {
            let status: Option<String> =
                sqlx::query_scalar("SELECT status FROM campaigns WHERE id = $1 AND tenant_id = $2")
                    .bind(campaign_id)
                    .bind(&tenant_id)
                    .fetch_optional(&self.db)
                    .await?;

            match status.as_deref() {
                // The live state: requeue failed recipients (suppressed rows
                // stay terminal — compliance) and hand the campaign back to
                // the drain phase.
                Some("resending") => {
                    let requeued = sqlx::query(
                        "UPDATE campaign_recipients \
                         SET status = 'queued', error = NULL, updated_at = NOW() \
                         WHERE campaign_id = $1 AND tenant_id = $2 AND status = 'failed'",
                    )
                    .bind(campaign_id)
                    .bind(&tenant_id)
                    .execute(&self.db)
                    .await?
                    .rows_affected();
                    sqlx::query(
                        "UPDATE campaigns SET status = 'sending', updated_at = NOW() \
                         WHERE id = $1 AND tenant_id = $2 AND status = 'resending'",
                    )
                    .bind(campaign_id)
                    .bind(&tenant_id)
                    .execute(&self.db)
                    .await?;
                    self.complete_job(job_id).await?;
                    tracing::info!(
                        campaign_id = %campaign_id,
                        tenant_id = %tenant_id,
                        requeued,
                        "resend job processed; failed recipients requeued"
                    );
                    report.jobs_completed += 1;
                }
                // Paused between the resend request and this tick: honor the
                // pause — put the job back for the post-resume tick.
                Some("paused") => {
                    sqlx::query(
                        "UPDATE campaign_jobs \
                         SET status = 'queued', started_at = NULL \
                         WHERE id = $1",
                    )
                    .bind(job_id)
                    .execute(&self.db)
                    .await?;
                    report.jobs_deferred += 1;
                }
                // Stale job (campaign moved on or deleted): complete it as a
                // no-op instead of churning it forever.
                _ => {
                    self.complete_job(job_id).await?;
                    report.jobs_completed += 1;
                }
            }
        }
        Ok(report)
    }

    async fn complete_job(&self, job_id: Uuid) -> Result<(), CampaignError> {
        sqlx::query(
            "UPDATE campaign_jobs \
             SET status = 'completed', completed_at = NOW() \
             WHERE id = $1",
        )
        .bind(job_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    // -- Phase 3: drain queued recipients ----------------------------------

    async fn drain_queued_recipients(&self) -> Result<TickReport, CampaignError> {
        let lease_cutoff = Utc::now() - chrono::Duration::seconds(RECIPIENT_LEASE_SECS);
        let claimed: Vec<ClaimedRecipient> = sqlx::query_as(
            "WITH claimed AS ( \
                 SELECT cr.id \
                 FROM campaign_recipients cr \
                 JOIN campaigns c ON c.id = cr.campaign_id AND c.tenant_id = cr.tenant_id \
                 WHERE c.status IN ('sending', 'resending') \
                   -- A/B holdouts are NOT deliverable yet: they wait for the
                   -- winner to be promoted (phase flipped to 'winner' by the
                   -- evaluation step). Claiming them early found no content
                   -- and marked the holdout failed.
                   AND (cr.phase IS NULL OR cr.phase IN ('test', 'winner')) \
                   AND (cr.status = 'queued' \
                        OR (cr.status = 'sending' AND cr.updated_at < $2)) \
                 ORDER BY cr.campaign_id, cr.created_at, cr.id \
                 LIMIT $1 \
                 FOR UPDATE OF cr SKIP LOCKED \
             ) \
             UPDATE campaign_recipients cr \
             SET status = 'sending', updated_at = NOW() \
             FROM claimed \
             WHERE claimed.id = cr.id \
             RETURNING cr.id, cr.tenant_id, cr.campaign_id, cr.contact_id, cr.email, \
                       cr.phase, cr.arm_index",
        )
        .bind(self.drain_batch_size)
        .bind(lease_cutoff)
        .fetch_all(&self.db)
        .await?
        .into_iter()
        .map(
            |(id, tenant_id, campaign_id, contact_id, email, phase, arm_index)| ClaimedRecipient {
                id,
                tenant_id,
                campaign_id,
                contact_id,
                email,
                phase,
                arm_index,
            },
        )
        .collect();

        if claimed.is_empty() {
            return Ok(TickReport::default());
        }

        // Resolve per-campaign send context once (sender + content + settings
        // + A/B arms).
        let campaign_ids: Vec<Uuid> = claimed.iter().map(|row| row.campaign_id).collect();
        let mut contexts: HashMap<Uuid, CampaignSendContext> = HashMap::new();
        {
            #[allow(clippy::type_complexity)]
            let rows: Vec<(
                Uuid,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                serde_json::Value,
                serde_json::Value,
                serde_json::Value,
                bool,
                bool,
            )> = sqlx::query_as(
                "SELECT id, tenant_id, COALESCE(subject, ''), from_email, from_name, \
                        reply_to, preview_text, html_body, text_body, template_id, \
                        COALESCE(variables, '{}'::jsonb), \
                        COALESCE(utm_params, '{}'::jsonb), \
                        COALESCE(settings, '{}'::jsonb), \
                        track_opens, track_clicks \
                 FROM campaigns WHERE id = ANY($1)",
            )
            .bind(&campaign_ids)
            .fetch_all(&self.db)
            .await?;
            for (
                id,
                tenant_id,
                subject,
                from_email,
                from_name,
                reply_to,
                preview_text,
                html,
                text,
                template_id,
                variables,
                utm_params,
                settings,
                track_opens,
                track_clicks,
            ) in rows
            {
                let template = match template_id.as_deref().filter(|id| !id.trim().is_empty()) {
                    None => None,
                    Some(template_id) => match fetch_template(&self.db, &tenant_id, template_id)
                        .await
                    {
                        Ok(template) => Some(template),
                        Err(error) => {
                            // A missing template is a campaign misconfiguration
                            // (rows fail honestly below); a template-store
                            // outage is infrastructure and defers the tick.
                            if matches!(error, crate::automations::AutomationError::Database(_)) {
                                return Err(CampaignError::Database(error.to_string()));
                            }
                            None
                        }
                    },
                };

                // Per-arm content for A/B campaigns (holdout sends use the
                // winner arm's content; test sends use their own).
                let mut arms: std::collections::HashMap<i32, ArmContent> =
                    std::collections::HashMap::new();
                let arm_rows: Vec<(i32, String, Option<String>)> = sqlx::query_as(
                    "SELECT arm_index, template_id, subject \
                     FROM campaign_ab_arms WHERE campaign_id = $1 ORDER BY arm_index",
                )
                .bind(id)
                .fetch_all(&self.db)
                .await?;
                for (arm_index, arm_template_id, arm_subject) in arm_rows {
                    let arm_template = match fetch_template(&self.db, &tenant_id, &arm_template_id)
                        .await
                    {
                        Ok(template) => Some(template),
                        Err(error) => {
                            if matches!(error, crate::automations::AutomationError::Database(_)) {
                                return Err(CampaignError::Database(error.to_string()));
                            }
                            None
                        }
                    };
                    arms.insert(
                        arm_index,
                        ArmContent {
                            subject: arm_subject,
                            template: arm_template,
                        },
                    );
                }

                let ip_pool = settings
                    .get("ipPool")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let throttle_rate = settings.get("throttleRate").and_then(|v| v.as_i64());

                // Documented `settings` (docs/api/endpoints/campaigns.md):
                // `sendTimeOptimization` schedules each recipient at their
                // optimal engagement hour and takes precedence over the
                // campaign-level distribution; `timezone` is the IANA zone
                // used to interpret those windows. A malformed timezone
                // (possible only through a directly seeded row — the API
                // validates IANA names) falls back to the tenant offset.
                let send_time_optimization = settings
                    .get("sendTimeOptimization")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let sto_offset_minutes = settings
                    .get("timezone")
                    .and_then(|v| v.as_str())
                    .filter(|tz| tz.parse::<chrono_tz::Tz>().is_ok())
                    .map(|_| analytics::send_time_optimizer::utc_offset_minutes_from_settings(&settings));

                contexts.insert(
                    id,
                    CampaignSendContext {
                        from_email: from_email.unwrap_or_default(),
                        from_name,
                        reply_to,
                        subject,
                        preview_text,
                        html,
                        text,
                        variables,
                        utm_params,
                        track_opens,
                        track_clicks,
                        ip_pool,
                        throttle_rate,
                        send_time_optimization,
                        sto_offset_minutes,
                        template,
                        arms,
                    },
                );
            }
        }

        // Throttle budgets: `settings.throttleRate` caps sends per hour per
        // campaign. Recipients beyond the budget are REQUEUED (not failed) —
        // the next tick continues where this one stopped.
        let mut budgets: HashMap<Uuid, i64> = HashMap::new();
        for (id, context) in &contexts {
            if let Some(rate) = context.throttle_rate.filter(|r| *r > 0) {
                let sent_last_hour: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM campaign_recipients \
                     WHERE campaign_id = $1 AND status = 'sent' \
                       AND updated_at > NOW() - INTERVAL '1 hour'",
                )
                .bind(id)
                .fetch_one(&self.db)
                .await?;
                budgets.insert(*id, (rate - sent_last_hour).max(0));
            }
        }

        let mut report = TickReport::default();
        for recipient in &claimed {
            match contexts.get(&recipient.campaign_id) {
                None => {
                    self.mark_recipient(recipient.id, "failed", "campaign vanished mid-send", None)
                        .await?;
                    report.recipients_failed += 1;
                }
                Some(context) if context.from_email.is_empty() => {
                    self.mark_recipient(
                        recipient.id,
                        "failed",
                        "campaign has no sender address",
                        None,
                    )
                    .await?;
                    report.recipients_failed += 1;
                }
                Some(context) if !context.has_content_for(recipient) => {
                    self.mark_recipient(
                        recipient.id,
                        "failed",
                        "campaign has no renderable content (template or html)",
                        None,
                    )
                    .await?;
                    report.recipients_failed += 1;
                }
                Some(context) => {
                    if let Some(remaining) = budgets.get_mut(&recipient.campaign_id) {
                        if *remaining <= 0 {
                            // Over the hourly budget: hand the claim back.
                            self.requeue_recipient(recipient.id).await?;
                            report.recipients_deferred += 1;
                            continue;
                        }
                        *remaining -= 1;
                    }
                    // `settings.sendTimeOptimization`: resolve this recipient's
                    // next optimal window and delay the queue row until then.
                    // A profile-read failure is transient infrastructure: the
                    // recipient is requeued (the contract is "optimal hour",
                    // not "immediately") rather than sent at a wrong time.
                    let scheduled_at = match self.scheduled_send_at(recipient, context).await {
                        Ok(scheduled_at) => scheduled_at,
                        Err(error) => {
                            tracing::warn!(
                                campaign_id = %recipient.campaign_id,
                                recipient = %recipient.id,
                                error = %error,
                                "send-time optimization failed; recipient requeued"
                            );
                            self.requeue_recipient(recipient.id).await?;
                            report.recipients_deferred += 1;
                            continue;
                        }
                    };
                    let outcome = self
                        .send_to_recipient(recipient, context, scheduled_at)
                        .await?;
                    report.merge(outcome);
                }
            }
        }
        Ok(report)
    }

    /// The per-recipient optimal send instant when `settings.sendTimeOptimization`
    /// is on: the next occurrence (strictly in the future) of the recipient's
    /// top engagement window in the campaign/tenant timezone. `None` means
    /// "send as soon as possible" (STO off, no optimizer injected, or an
    /// empty window list).
    async fn scheduled_send_at(
        &self,
        recipient: &ClaimedRecipient,
        context: &CampaignSendContext,
    ) -> Result<Option<chrono::DateTime<Utc>>, String> {
        if !context.send_time_optimization {
            return Ok(None);
        }
        let Some(optimizer) = self.send_time.as_ref() else {
            // No optimizer injected (test harness / STO-capable deployment
            // without the engine): sending now is the honest fallback, and
            // it is logged rather than silent.
            tracing::warn!(
                campaign_id = %recipient.campaign_id,
                "settings.sendTimeOptimization is on but no optimizer is configured; sending immediately"
            );
            return Ok(None);
        };

        // Tenant-scoped profile read (the engine filters events by
        // tenant_id); the campaign's own timezone overrides the tenant's.
        let result = optimizer
            .get_optimal_window_for_tenant_with_offset(
                &recipient.tenant_id,
                &recipient.email,
                context.sto_offset_minutes,
            )
            .await
            .map_err(|error| format!("send-time profile read failed: {error}"))?;
        let Some(window) = result.windows.first() else {
            return Ok(None);
        };
        Ok(Some(analytics::send_time_optimizer::next_occurrence_utc(
            Utc::now(),
            window,
            result.utc_offset_minutes,
        )))
    }

    /// The send ladder for ONE recipient: admission (suppression + quota) →
    /// render → one transaction writing `messages` + `email_queue`. Returns
    /// the tick delta. `scheduled_at` (from
    /// [`Self::scheduled_send_at`]) is the send-time-optimization window; the
    /// email processor's claim only picks the row up when due.
    async fn send_to_recipient(
        &self,
        recipient: &ClaimedRecipient,
        context: &CampaignSendContext,
        scheduled_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<TickReport, CampaignError> {
        let idempotency_key = format!(
            "campaign:{}:{}",
            recipient.campaign_id, recipient.contact_id
        );

        // 1. Admission — the ONE shared gate, explicit marketing category
        //    (campaign mail is commercial mail; suppression applies).
        let admission = match self
            .admission
            .admit(SendAdmissionRequest {
                tenant_id: &recipient.tenant_id,
                meter: AdmissionMeter::FilteredRecipients(std::slice::from_ref(&recipient.email)),
                idempotency_key: Some(&idempotency_key),
                idempotency_item: None,
                category: Some(message_category::MARKETING),
            })
            .await
        {
            Ok(admission) => admission,
            Err(SendAdmissionError::Suppressed(_)) => {
                // Terminal: a suppressed recipient is never retried, not even
                // by a resend (the email processor re-checks independently).
                self.mark_recipient(recipient.id, "suppressed", "recipient is suppressed", None)
                    .await?;
                return Ok(TickReport {
                    recipients_suppressed: 1,
                    ..TickReport::default()
                });
            }
            Err(SendAdmissionError::InvalidCategory { .. }) => {
                // Server-owned constant failed validation: a programming
                // error. Terminal, loud, never a retry loop.
                self.mark_recipient(
                    recipient.id,
                    "failed",
                    "invalid server-owned message category",
                    None,
                )
                .await?;
                return Ok(TickReport {
                    recipients_failed: 1,
                    ..TickReport::default()
                });
            }
            Err(SendAdmissionError::ConsentRefused { email, reason }) => {
                // F4 consent gate: a marketing recipient without an active
                // consent record is a TERMINAL refusal for this recipient
                // (retrying cannot create consent). Same terminal shape as
                // the suppressed arm; the recipient row is never re-claimed.
                tracing::info!(
                    campaign_id = %recipient.campaign_id,
                    email = %email,
                    reason = %reason,
                    "campaign recipient refused admission: marketing consent missing (terminal)"
                );
                self.mark_recipient(
                    recipient.id,
                    "suppressed",
                    "marketing consent required",
                    None,
                )
                .await?;
                return Ok(TickReport {
                    recipients_suppressed: 1,
                    ..TickReport::default()
                });
            }
            // Quota exhaustion and store unavailability are TRANSIENT: put the
            // row back for the next tick instead of failing it.
            Err(
                error @ (SendAdmissionError::QuotaExceeded
                | SendAdmissionError::MeteringUnavailable(_)
                | SendAdmissionError::SuppressionUnavailable(_)
                | SendAdmissionError::ConsentUnavailable(_)),
            ) => {
                tracing::warn!(
                    campaign_id = %recipient.campaign_id,
                    recipient = %recipient.id,
                    error = %error,
                    "campaign send deferred; recipient requeued"
                );
                self.requeue_recipient(recipient.id).await?;
                return Ok(TickReport {
                    recipients_deferred: 1,
                    ..TickReport::default()
                });
            }
        };
        let quota_event_id = admission.event_id();
        let admitted_category = admission.category().to_string();

        // 2. Render per contact ({{name}} / {{first_name}} / {{email}},
        //    HTML-escaped in the HTML part — same policy as automations).
        let (template, subject_override, _) = context.content_for(recipient);
        let rendered = render_content(context, template, subject_override, &recipient.email);

        // 3. One transaction: sender-domain gate + message + queue row
        //    (exactly-once through the per-recipient idempotency key).
        let message_id = Uuid::new_v4();
        let queue_id = Uuid::new_v4();
        let now = Utc::now();
        // Metadata carries the per-message knobs the processor honors:
        // display name, per-campaign tracking toggles, and the dedicated-IP
        // pool (`dedicated_ips.ses_pool_name`) for SES configuration-set
        // routing.
        let mut metadata = serde_json::json!({
            "source": "campaigns",
            "campaign_id": recipient.campaign_id.to_string(),
            "contact_id": recipient.contact_id.to_string(),
            "quota_event_id": quota_event_id.to_string(),
            "track_opens": context.track_opens,
            "track_clicks": context.track_clicks,
        });
        if let Some(from_name) = context.from_name.as_deref() {
            metadata["from_name"] = serde_json::Value::String(from_name.to_string());
        }
        if let Some(pool) = context.ip_pool.as_deref() {
            metadata["ip_pool"] = serde_json::Value::String(pool.to_string());
        }
        if let Some(phase) = recipient.phase.as_deref() {
            metadata["ab_phase"] = serde_json::Value::String(phase.to_string());
        }
        if let Some(arm) = recipient.arm_index {
            metadata["ab_arm"] = serde_json::json!(arm);
        }

        let mut tx = match self.db.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                let _ = admission.rollback().await;
                return self
                    .fail_recipient(recipient, &format!("enqueue_failed: {error}"))
                    .await;
            }
        };

        // Ready sender-domain resolution under the transaction — the exact
        // SQL the REST/automations/sales paths use.
        let domain_id = match resolve_sender_domain_id(
            &mut tx,
            &recipient.tenant_id,
            &context.from_email,
        )
        .await
        {
            Ok(domain_id) => domain_id,
            Err(error) => {
                drop(tx);
                let _ = admission.rollback().await;
                return self
                    .fail_recipient(recipient, &format!("enqueue_failed: {error}"))
                    .await;
            }
        };
        let Some(domain_id) = domain_id else {
            drop(tx);
            let _ = admission.rollback().await;
            self.mark_recipient(
                recipient.id,
                "failed",
                "sender domain not verified/DKIM-ready",
                None,
            )
            .await?;
            return Ok(TickReport {
                recipients_failed: 1,
                ..TickReport::default()
            });
        };

        let inserted = sqlx::query(
            "INSERT INTO messages \
             (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, \
              html_body, text_body, status, tags, metadata, scheduled_at, created_at, \
              idempotency_key, message_category) \
             VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', $10, $11, $12, \
                     $13, $14, $15) \
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
        )
        .bind(message_id)
        .bind(&recipient.tenant_id)
        .bind(&context.from_email)
        .bind(serde_json::json!([recipient.email]))
        .bind(serde_json::Value::Null)
        .bind(serde_json::Value::Null)
        .bind(&rendered.subject)
        .bind(&rendered.html)
        .bind(&rendered.text)
        .bind(serde_json::json!(["campaign"]))
        .bind(&metadata)
        .bind(scheduled_at)
        .bind(now)
        .bind(&idempotency_key)
        .bind(&admitted_category)
        .execute(&mut *tx)
        .await;

        let inserted = match inserted {
            Ok(inserted) => inserted,
            Err(error) => {
                drop(tx);
                let _ = admission.rollback().await;
                return self
                    .fail_recipient(recipient, &format!("enqueue_failed: {error}"))
                    .await;
            }
        };

        if inserted.rows_affected() == 0 {
            // This (campaign, contact) already enqueued in a previous attempt
            // (the crash window between enqueue and bookkeeping): reuse the
            // existing message instead of sending again.
            let existing: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM messages WHERE tenant_id = $1 AND idempotency_key = $2",
            )
            .bind(&recipient.tenant_id)
            .bind(&idempotency_key)
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or(None);
            if let Err(error) = tx.commit().await {
                let _ = admission.rollback().await;
                return self
                    .fail_recipient(recipient, &format!("enqueue_failed: {error}"))
                    .await;
            }
            admission.commit();
            self.mark_recipient(recipient.id, "sent", "", existing.or(Some(message_id)))
                .await?;
            return Ok(TickReport {
                recipients_sent: 1,
                ..TickReport::default()
            });
        }

        let queued = sqlx::query(
            "INSERT INTO email_queue \
             (id, message_id, tenant_id, domain_id, from_address, to_addresses, subject, \
              \"from\", \"to\", html, text, tags, metadata, headers, scheduled_at, priority, \
              status, created_at, updated_at, message_category, campaign_id, contact_id) \
             VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, ARRAY[$6], $7, $5, $6, $8, $9, \
                     $10, $11, $12, $13, 5, 'pending', $14, $14, $15, $16::uuid, $17::uuid)",
        )
        .bind(queue_id)
        .bind(message_id)
        .bind(&recipient.tenant_id)
        .bind(&domain_id)
        .bind(&context.from_email)
        .bind(&recipient.email)
        .bind(&rendered.subject)
        .bind(&rendered.html)
        .bind(&rendered.text)
        // email_queue.tags is TEXT[] (messages.tags is JSONB) — the same
        // split the automations ladder binds.
        .bind(vec!["campaign".to_string()])
        .bind(&metadata)
        // F26 server-written MIME header map: the `custom` key marks the
        // structured shape (a bare object would be read as a legacy flat
        // custom-header map and emit a literal `reply_to` header). Carries
        // the campaign's Reply-To as a structured mailbox.
        .bind(match context.reply_to.as_deref() {
            Some(reply_to) => serde_json::json!({
                "to": [],
                "reply_to": reply_to,
                "custom": {},
            }),
            None => serde_json::json!({}),
        })
        // Send-time optimization: the processor's claim SQL only picks the
        // row up when `scheduled_at IS NULL OR scheduled_at <= NOW()`.
        .bind(scheduled_at)
        .bind(now)
        .bind(&admitted_category)
        .bind(recipient.campaign_id)
        .bind(recipient.contact_id)
        .execute(&mut *tx)
        .await;

        if let Err(error) = queued {
            drop(tx);
            let _ = admission.rollback().await;
            return self
                .fail_recipient(recipient, &format!("enqueue_failed: {error}"))
                .await;
        }

        if let Err(error) = tx.commit().await {
            let _ = admission.rollback().await;
            return self
                .fail_recipient(recipient, &format!("enqueue_failed: {error}"))
                .await;
        }
        admission.commit();

        self.mark_recipient(recipient.id, "sent", "", Some(message_id))
            .await?;
        Ok(TickReport {
            recipients_sent: 1,
            ..TickReport::default()
        })
    }

    /// Terminal per-recipient failure: record the error under an attempt cap.
    /// Under the cap the row returns to `queued` (a transient enqueue failure
    /// must not park the recipient permanently); at the cap it parks `failed`
    /// for a resend. Never panics, never blocks the batch.
    async fn fail_recipient(
        &self,
        recipient: &ClaimedRecipient,
        error: &str,
    ) -> Result<TickReport, CampaignError> {
        let error = truncate_error(error);
        let parked: bool = sqlx::query_scalar(
            "UPDATE campaign_recipients \
             SET attempts = attempts + 1, \
                 error = $2, \
                 status = CASE WHEN attempts + 1 >= $3 THEN 'failed' ELSE 'queued' END, \
                 updated_at = NOW() \
             WHERE id = $1 \
             RETURNING status = 'failed'",
        )
        .bind(recipient.id)
        .bind(&error)
        .bind(MAX_RECIPIENT_ATTEMPTS)
        .fetch_one(&self.db)
        .await?;
        if parked {
            tracing::warn!(
                campaign_id = %recipient.campaign_id,
                recipient = %recipient.id,
                error = %error,
                "campaign recipient send failed"
            );
            Ok(TickReport {
                recipients_failed: 1,
                ..TickReport::default()
            })
        } else {
            Ok(TickReport {
                recipients_deferred: 1,
                ..TickReport::default()
            })
        }
    }

    async fn mark_recipient(
        &self,
        id: Uuid,
        status: &str,
        error: &str,
        message_id: Option<Uuid>,
    ) -> Result<(), CampaignError> {
        sqlx::query(
            "UPDATE campaign_recipients \
             SET status = $2, error = NULLIF($3, ''), message_id = COALESCE($4, message_id), \
                 updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(error)
        .bind(message_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn requeue_recipient(&self, id: Uuid) -> Result<(), CampaignError> {
        sqlx::query(
            "UPDATE campaign_recipients SET status = 'queued', updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    // -- Phase 4: finalize -------------------------------------------------

    /// A `sending`/`resending` campaign with recipient rows but nothing left
    /// in flight converges: `sent` when every recipient was enqueued, `partial`
    /// otherwise; `sent_count` becomes the real per-recipient count.
    async fn finalize_finished_campaigns(&self) -> Result<TickReport, CampaignError> {
        let finished: Vec<Uuid> = sqlx::query_scalar(
            "SELECT c.id FROM campaigns c \
             WHERE c.status IN ('sending', 'resending') \
               AND EXISTS (SELECT 1 FROM campaign_recipients cr WHERE cr.campaign_id = c.id) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM campaign_recipients cr \
                   WHERE cr.campaign_id = c.id AND cr.status IN ('queued', 'sending') \
               ) \
             LIMIT $1 \
             FOR UPDATE SKIP LOCKED",
        )
        .bind(self.batch_size)
        .fetch_all(&self.db)
        .await?;

        let mut report = TickReport::default();
        for campaign_id in finished {
            let (sent, failed): (i64, i64) = sqlx::query_as(
                "SELECT \
                    COUNT(*) FILTER (WHERE status = 'sent'), \
                    COUNT(*) FILTER (WHERE status IN ('failed', 'suppressed')) \
                 FROM campaign_recipients WHERE campaign_id = $1",
            )
            .bind(campaign_id)
            .fetch_one(&self.db)
            .await?;

            let new_status = if failed > 0 { "partial" } else { "sent" };
            let updated = sqlx::query(
                "UPDATE campaigns \
                 SET status = $2, sent_count = $3, updated_at = NOW() \
                 WHERE id = $1 AND status IN ('sending', 'resending')",
            )
            .bind(campaign_id)
            .bind(new_status)
            .bind(i32::try_from(sent).unwrap_or(i32::MAX))
            .execute(&self.db)
            .await?
            .rows_affected();
            if updated > 0 {
                let (tenant_id, ab_winner): (String, Option<serde_json::Value>) = sqlx::query_as(
                    "SELECT tenant_id, ab_config->'winnerArm' FROM campaigns WHERE id = $1",
                )
                .bind(campaign_id)
                .fetch_one(&self.db)
                .await?;
                enqueue_campaign_event_webhooks(
                    &self.db,
                    &tenant_id,
                    "campaign.completed",
                    serde_json::json!({
                        "id": format!("evt_{}", Uuid::new_v4().simple()),
                        "type": "campaign.completed",
                        "tenantId": tenant_id,
                        "timestamp": Utc::now().to_rfc3339(),
                        "data": {
                            "campaign_id": campaign_id.to_string(),
                            "status": new_status,
                            "sent": sent,
                            "failed": failed,
                            "ab_winner_arm": ab_winner,
                        },
                    }),
                )
                .await;
                report.campaigns_completed += 1;
            }
        }
        Ok(report)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a JSONB array of UUID strings (schema-checked to be an array;
/// tolerate junk elements instead of failing the campaign).
fn uuid_array(value: &serde_json::Value) -> Vec<Uuid> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect()
        })
        .unwrap_or_default()
}

/// Enqueue one lifecycle event for every active webhook of the tenant
/// subscribed to it. Delivery (retries, circuit breaker, SSRF guard) is the
/// worker webhook processor's job — the campaign consumer only enqueues, the
/// same division the automation executor uses.
async fn enqueue_campaign_event_webhooks(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    event_type: &str,
    payload: serde_json::Value,
) {
    let webhook_ids: Vec<String> = match sqlx::query_scalar(
        "SELECT id FROM webhooks \
         WHERE tenant_id = $1 AND enabled = true \
           AND (events ? $2 OR events ? '*')",
    )
    .bind(tenant_id)
    .bind(event_type)
    .fetch_all(pool)
    .await
    {
        Ok(ids) => ids,
        Err(error) => {
            tracing::warn!(error = %error, event_type, "campaign webhook subscription lookup failed");
            return;
        }
    };
    for webhook_id in webhook_ids {
        let queue_id = format!("whj_{}", Uuid::new_v4().simple());
        if let Err(error) = sqlx::query(
            "INSERT INTO webhook_queue \
             (id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at) \
             VALUES ($1, $2, $3, $4, $5, 'pending', 1, NOW())",
        )
        .bind(&queue_id)
        .bind(&webhook_id)
        .bind(tenant_id)
        .bind(event_type)
        .bind(&payload)
        .execute(pool)
        .await
        {
            tracing::warn!(error = %error, event_type, webhook_id, "campaign webhook enqueue failed");
        }
    }
}

/// Truncate recorded errors to a bounded size (a 4 KB SQL error has no place
/// in a per-recipient status column).
fn truncate_error(error: &str) -> String {
    if error.len() <= MAX_ERROR_LEN {
        error.to_string()
    } else {
        let mut cut = MAX_ERROR_LEN;
        while !error.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &error[..cut])
    }
}

/// The rendered send for one contact.
struct RenderedCampaign {
    subject: String,
    html: Option<String>,
    text: Option<String>,
}

/// Minimal `{{name}}`-style interpolation for the campaign subject and the
/// template bodies, HTML-escaping in the HTML part — the same policy as the
/// automations renderer (which renders from an automation EventContext, not a
/// bare contact). Unknown placeholders are left untouched; the delivery
/// pipeline substitutes `{{unsubscribe_url}}` itself for marketing mail.
/// Render one recipient's copy from its resolved content: the arm/campaign
/// template or the campaign's inline html/text, with global variables merged
/// (contact-derived identity always wins), the preview-text preheader, and
/// UTM-decorated links.
fn render_content(
    context: &CampaignSendContext,
    template: Option<&TemplateContent>,
    subject_override: Option<&str>,
    email: &str,
) -> RenderedCampaign {
    let name = contact_name(email);
    let first_name = name
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();

    // Globals are applied FIRST so contact identity always wins a collision.
    let mut text_vars: Vec<(String, String)> = Vec::new();
    if let Some(globals) = context.variables.as_object() {
        for (key, value) in globals {
            if let Some(value) = value.as_str() {
                text_vars.push((key.clone(), value.to_string()));
            }
        }
    }
    let mut html_vars: Vec<(String, String)> = text_vars
        .iter()
        .map(|(k, v)| (k.clone(), escape_html(v)))
        .collect();
    text_vars.push(("email".into(), email.to_string()));
    text_vars.push(("name".into(), name.clone()));
    text_vars.push(("first_name".into(), first_name.clone()));
    html_vars.push(("email".into(), escape_html(email)));
    html_vars.push(("name".into(), escape_html(&name)));
    html_vars.push(("first_name".into(), escape_html(&first_name)));

    // Subject precedence: arm override > campaign subject > template subject.
    let subject_source = subject_override
        .filter(|s| !s.is_empty())
        .or_else(|| (!context.subject.is_empty()).then_some(context.subject.as_str()))
        .or_else(|| template.map(|t| t.subject.as_str()))
        .unwrap_or_default();
    let subject = apply_vars_owned(subject_source, &text_vars);

    let html_source = template
        .and_then(|t| t.html_body.as_deref())
        .or(context.html.as_deref());
    let text_source = template
        .and_then(|t| t.text_body.as_deref())
        .or(context.text.as_deref());

    let rendered_html = html_source.map(|body| {
        let mut out = apply_vars_owned(body, &html_vars);
        if let Some(preview) = context
            .preview_text
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            // The standard preheader: hidden ahead of the body so inbox
            // listings show the chosen snippet instead of body text.
            let preheader = format!(
                "<div style=\"display:none;font-size:1px;color:#ffffff;line-height:1px;\
                 max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all\">{}</div>",
                escape_html(preview)
            );
            out = format!("{preheader}{out}");
        }
        decorate_utm(&out, &context.utm_params)
    });

    RenderedCampaign {
        subject,
        html: rendered_html,
        text: text_source.map(|body| apply_vars_owned(body, &text_vars)),
    }
}

fn apply_vars_owned(body: &str, vars: &[(String, String)]) -> String {
    let mut out = body.to_string();
    for (name, value) in vars {
        out = out.replace(&format!("{{{{{name}}}}}"), value);
    }
    out
}

/// Append the configured UTM parameters to every absolute http(s) link in
/// the HTML body (existing query strings preserved; a parameter already
/// present on the URL is left untouched so author-set values win).
fn decorate_utm(html: &str, utm_params: &serde_json::Value) -> String {
    let Some(params) = utm_params.as_object() else {
        return html.to_string();
    };
    if params.is_empty() {
        return html.to_string();
    }
    let mut out = String::with_capacity(html.len() + 64);
    let mut rest = html;
    while let Some(idx) = rest.find("href=") {
        let (before, from) = rest.split_at(idx + "href=".len());
        out.push_str(before);
        let (quote, remainder) = match from.chars().next() {
            Some(q @ ('"' | '\'')) => (q, &from[q.len_utf8()..]),
            _ => {
                // Malformed/unquoted href: leave the rest untouched.
                out.push_str(from);
                rest = "";
                break;
            }
        };
        match remainder.find(quote) {
            Some(end) => {
                let url = &remainder[..end];
                let decorated = if url.starts_with("http://") || url.starts_with("https://") {
                    let separator = if url.contains('?') { '&' } else { '?' };
                    let mut additions: Vec<String> = Vec::new();
                    for key in ["source", "medium", "campaign", "term", "content"] {
                        if let Some(value) = params.get(key).and_then(|v| v.as_str()) {
                            let marker = format!("utm_{key}=");
                            if !url.contains(&marker) {
                                additions.push(format!("utm_{key}={}", urlencode_component(value)));
                            }
                        }
                    }
                    if additions.is_empty() {
                        url.to_string()
                    } else {
                        format!("{url}{separator}{}", additions.join("&"))
                    }
                } else {
                    url.to_string()
                };
                out.push(quote);
                out.push_str(&decorated);
                out.push(quote);
                rest = &remainder[end + quote.len_utf8()..];
            }
            None => {
                out.push_str(from);
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Percent-encode one query component (RFC 3986 unreserved set kept).
fn urlencode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The display name for a recipient address: the local part, punctuated
/// splits stripped (`jane.doe@example.com` renders "jane doe"). An empty
/// local part (`@host`) falls back to the raw address rather than rendering
/// an empty name.
fn contact_name(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("");
    if local.is_empty() {
        email.to_string()
    } else {
        local.replace(['.', '_', '-'], " ")
    }
}

/// Ready sender-domain resolution with a row lock held through the queue
/// insert — the exact SQL the REST, automations and sales paths use. Returns
/// `None` when the sender address has no domain or the domain is not
/// verified + DKIM-ready (the send ladder's skip condition).
async fn resolve_sender_domain_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    from: &str,
) -> Result<Option<String>, sqlx::Error> {
    let Some(sender_domain) = sender_domain(from) else {
        return Ok(None);
    };
    let ses_enabled = apexmail_lib::transport::email_transport_is_ses(
        std::env::var("EMAIL_TRANSPORT_TYPE").ok().as_deref(),
    );
    sqlx::query_scalar(
        "SELECT id::text FROM domains
                 WHERE tenant_id = $1 AND name = $2 AND status = 'verified'
                     AND dkim_enabled = true
                     AND dkim_selector IS NOT NULL AND dkim_public_key IS NOT NULL AND dkim_private_key IS NOT NULL
                     AND dkim_private_key LIKE 'dkim:v1:%'
                     AND ($3::boolean = false OR ses_verified = true)
                 LIMIT 1 FOR SHARE",
    )
    .bind(tenant_id)
    .bind(&sender_domain)
    .bind(ses_enabled)
    .fetch_optional(&mut **tx)
    .await
}

fn sender_domain(from: &str) -> Option<String> {
    from.rsplit_once('@')
        .map(|(_, domain)| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use std::sync::Arc;

    use billing_service::send_admission::SendAdmissionBackend;
    use billing_service::usage::{QuotaRecordResult, UsageError};
    use serde_json::Value;

    // One fresh canonical database per test so claims cannot race other suites.
    async fn fresh_pool(test_name: &str, suffix: &str) -> Option<PgPool> {
        crate::test_support::canonical_pool(test_name, suffix).await
    }

    /// A unique per-run tenant id, capped at 26 chars (`VARCHAR(26)`).
    fn fresh_tenant(label: &str) -> String {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let prefix: String = label.chars().take(13).collect();
        format!("{prefix}-{}", &suffix[..12])
    }

    /// In-memory admission backend: quota limit, suppression set, duplicate
    /// detection — the same harness the automations executor tests use.
    #[derive(Debug)]
    struct FakeAdmission {
        limit: AtomicI64,
        used: AtomicI64,
        reserves: AtomicUsize,
        events: std::sync::Mutex<std::collections::HashSet<Uuid>>,
        suppressed: std::sync::Mutex<Vec<String>>,
    }

    impl FakeAdmission {
        fn new() -> Self {
            Self {
                limit: AtomicI64::new(-1),
                used: AtomicI64::new(0),
                reserves: AtomicUsize::new(0),
                events: std::sync::Mutex::new(std::collections::HashSet::new()),
                suppressed: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn suppress(&self, email: &str) {
            self.suppressed
                .lock()
                .unwrap()
                .push(email.trim().to_ascii_lowercase());
        }

        fn set_limit(&self, limit: i64) {
            self.limit.store(limit, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl SendAdmissionBackend for FakeAdmission {
        async fn record_send_usage(
            &self,
            _tenant_id: &str,
            quantity: i64,
            event_id: Uuid,
        ) -> Result<QuotaRecordResult, UsageError> {
            self.reserves.fetch_add(1, Ordering::SeqCst);
            let mut events = self.events.lock().unwrap();
            if events.contains(&event_id) {
                return Ok(QuotaRecordResult {
                    allowed: true,
                    current: self.used.load(Ordering::SeqCst),
                    duplicate: true,
                });
            }
            let limit = self.limit.load(Ordering::SeqCst);
            let used = self.used.load(Ordering::SeqCst);
            if limit >= 0 && used + quantity > limit {
                return Ok(QuotaRecordResult {
                    allowed: false,
                    current: used,
                    duplicate: false,
                });
            }
            self.used.fetch_add(quantity, Ordering::SeqCst);
            events.insert(event_id);
            Ok(QuotaRecordResult {
                allowed: true,
                current: used + quantity,
                duplicate: false,
            })
        }

        async fn rollback_send_usage(
            &self,
            _tenant_id: &str,
            quantity: i64,
            event_id: Uuid,
            _recorded_at: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), UsageError> {
            let removed = self.events.lock().unwrap().remove(&event_id);
            if removed {
                self.used.fetch_sub(quantity, Ordering::SeqCst);
            }
            Ok(())
        }

        async fn suppressed_recipients(
            &self,
            _tenant_id: &str,
            canonical_recipients: &[String],
        ) -> Result<Vec<String>, String> {
            let suppressed = self.suppressed.lock().unwrap();
            Ok(canonical_recipients
                .iter()
                .filter(|recipient| suppressed.contains(recipient))
                .cloned()
                .collect())
        }
    }

    fn executor(pool: &PgPool, backend: Arc<FakeAdmission>) -> CampaignExecutor {
        crate::test_support::install_test_tracing();
        CampaignExecutor::new(
            pool.clone(),
            SendAdmissionService::new(backend),
            "campaign-lib",
        )
        .with_batch_size(50)
        .with_drain_batch_size(50)
    }

    async fn insert_tenant(pool: &PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) \
             VALUES ($1, $2, $3, 'free', 'active')",
        )
        .bind(tenant)
        .bind(format!("Campaign Lib {tenant}"))
        .bind(format!("camplib-{tenant}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    }

    /// A verified, DKIM-ready sender domain (the exact readiness contract the
    /// enqueue transaction enforces).
    async fn insert_domain(pool: &PgPool, tenant: &str) -> String {
        let domain = format!(
            "camplib-{}.example.com",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, \
             ses_verified, dkim_selector, dkim_public_key, dkim_private_key) \
             VALUES ($1, $2, $3, 'verified', true, true, true, 'lib-selector', 'lib-public', \
                     'dkim:v1:lib-test')",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(&domain)
        .execute(pool)
        .await
        .expect("insert domain");
        domain
    }

    async fn insert_template(pool: &PgPool, tenant: &str) -> String {
        let id = format!("tpl_{}", &Uuid::new_v4().simple().to_string()[..16]);
        sqlx::query(
            "INSERT INTO templates (id, tenant_id, name, slug, subject, html_body, text_body) \
             VALUES ($1, $2, $3, $4, 'Hello {{first_name}}', '<p>Hi {{name}} ({{email}})</p>', \
                     'Hi {{first_name}}')",
        )
        .bind(&id)
        .bind(tenant)
        .bind(format!("Template {id}"))
        .bind(&id)
        .execute(pool)
        .await
        .expect("insert template");
        id
    }

    async fn insert_list(pool: &PgPool, tenant: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO lists (id, tenant_id, name, opt_in_mode) VALUES ($1, $2, $3, 'single_opt_in')",
        )
        .bind(id)
        .bind(tenant)
        .bind(format!("List {id}"))
        .execute(pool)
        .await
        .expect("insert list");
        id
    }

    async fn insert_contact(pool: &PgPool, tenant: &str, email: &str, status: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, email, name, status) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(tenant)
        .bind(email)
        .bind(email.split('@').next().unwrap_or("Contact"))
        .bind(status)
        .execute(pool)
        .await
        .expect("insert contact");
        id
    }

    async fn subscribe(pool: &PgPool, list_id: Uuid, contact_id: Uuid) {
        sqlx::query(
            "INSERT INTO list_subscribers (list_id, contact_id, status) VALUES ($1, $2, 'active')",
        )
        .bind(list_id)
        .bind(contact_id)
        .execute(pool)
        .await
        .expect("subscribe");
    }

    /// A campaign with a ready sender + template + one include list.
    async fn insert_ready_campaign(
        pool: &PgPool,
        tenant: &str,
        status: &str,
        scheduled_at: Option<chrono::DateTime<Utc>>,
    ) -> Uuid {
        let domain = insert_domain(pool, tenant).await;
        let template_id = insert_template(pool, tenant).await;
        let from = format!("news@{domain}");
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO campaigns (id, tenant_id, name, subject, template_id, from_email, \
             status, scheduled_at, sent_count, list_ids) \
             VALUES ($1, $2, $3, 'Hello {{first_name}}', $4, $5, $6, $7, 0, $8::jsonb)",
        )
        .bind(id)
        .bind(tenant)
        .bind(format!("Campaign {id}"))
        .bind(&template_id)
        .bind(&from)
        .bind(status)
        .bind(scheduled_at)
        .bind("[]")
        .execute(pool)
        .await
        .expect("insert campaign");
        id
    }

    async fn campaign_status(pool: &PgPool, campaign_id: Uuid) -> (String, i32) {
        let row: (String, i32) =
            sqlx::query_as("SELECT status, sent_count FROM campaigns WHERE id = $1")
                .bind(campaign_id)
                .fetch_one(pool)
                .await
                .expect("campaign status");
        row
    }

    async fn recipient_statuses(pool: &PgPool, campaign_id: Uuid) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT email, status FROM campaign_recipients \
             WHERE campaign_id = $1 ORDER BY email",
        )
        .bind(campaign_id)
        .fetch_all(pool)
        .await
        .expect("recipient statuses")
    }

    // -----------------------------------------------------------------------
    // Pure helpers
    // -----------------------------------------------------------------------

    #[test]
    fn uuid_array_tolerates_junk_elements_and_non_arrays() {
        let ok = uuid_array(&serde_json::json!([
            "11111111-1111-1111-1111-111111111111",
            "junk"
        ]));
        assert_eq!(ok.len(), 1, "junk elements are dropped, not fatal");
        assert!(uuid_array(&serde_json::json!("not-an-array")).is_empty());
        assert!(uuid_array(&serde_json::json!([null])).is_empty());
    }

    #[test]
    fn truncate_error_respects_char_boundaries() {
        assert_eq!(truncate_error("short"), "short");
        let long = "ä".repeat(600);
        let truncated = truncate_error(&long);
        assert!(truncated.len() <= MAX_ERROR_LEN + 3);
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn contact_name_strips_local_part_punctuation() {
        assert_eq!(contact_name("jane.doe@example.com"), "jane doe");
        assert_eq!(contact_name("no-local@x.y"), "no local");
        assert_eq!(contact_name("@nowhere"), "@nowhere");
    }

    #[test]
    fn render_escapes_html_and_leaves_unknown_placeholders() {
        let template = TemplateContent {
            subject: "Hi {{first_name}}".to_string(),
            html_body: Some("<b>{{name}}</b> {{unknown_tag}}".to_string()),
            text_body: Some("{{email}}".to_string()),
        };
        let ctx = CampaignSendContext {
            from_name: None,
            reply_to: None,
            preview_text: None,
            html: None,
            text: None,
            variables: serde_json::json!({}),
            utm_params: serde_json::json!({}),
            track_opens: true,
            track_clicks: true,
            ip_pool: None,
            throttle_rate: None,
            send_time_optimization: false,
            sto_offset_minutes: None,
            arms: std::collections::HashMap::new(),
            from_email: "news@example.test".into(),
            subject: "Campaign subject".into(),
            template: Some(template),
        };
        let rendered = render_content(
            &ctx,
            ctx.template.as_ref(),
            None,
            "ada.lovelace@example.com",
        );
        assert_eq!(rendered.subject, "Campaign subject");
        assert_eq!(
            rendered.html.as_deref(),
            Some("<b>ada lovelace</b> {{unknown_tag}}")
        );
        assert_eq!(rendered.text.as_deref(), Some("ada.lovelace@example.com"));

        // An empty campaign subject falls back to the template subject.
        let fallback_ctx = CampaignSendContext {
            from_name: None,
            reply_to: None,
            preview_text: None,
            html: None,
            text: None,
            variables: serde_json::json!({}),
            utm_params: serde_json::json!({}),
            track_opens: true,
            track_clicks: true,
            ip_pool: None,
            throttle_rate: None,
            send_time_optimization: false,
            sto_offset_minutes: None,
            arms: std::collections::HashMap::new(),
            from_email: "news@example.test".into(),
            subject: String::new(),
            template: Some(TemplateContent {
                subject: "Hi {{first_name}}".to_string(),
                html_body: None,
                text_body: None,
            }),
        };
        let rendered = render_content(
            &fallback_ctx,
            fallback_ctx.template.as_ref(),
            None,
            "ada.lovelace@example.com",
        );
        assert_eq!(rendered.subject, "Hi ada");
    }

    // -----------------------------------------------------------------------
    // Executor (DB-backed; fresh canonical database per test)
    // -----------------------------------------------------------------------

    /// THE pipeline: a scheduled campaign comes due → audience expands →
    /// drain sends every recipient through admission + enqueue → the campaign
    /// converges `sent` with a real sent_count and messages in `queued`.
    #[tokio::test]
    async fn scheduled_campaign_drains_to_sent_with_queued_messages() {
        let Some(pool) = fresh_pool("campaigns_drain_sent", "drain_sent").await else {
            return;
        };
        let tenant = fresh_tenant("camp-sent");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend.clone());

        let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        let list = insert_list(&pool, &tenant).await;
        let mut emails = Vec::new();
        for i in 0..3 {
            let email = format!(
                "rcpt-{i}-{}@example.test",
                &Uuid::new_v4().simple().to_string()[..8]
            );
            let contact = insert_contact(&pool, &tenant, &email, "active").await;
            subscribe(&pool, list, contact).await;
            emails.push(email);
        }
        sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
            .bind(campaign)
            .bind(serde_json::json!([list.to_string()]).to_string())
            .execute(&pool)
            .await
            .expect("attach list");

        // ONE tick runs the whole pipeline: claim the due campaign, expand
        // its audience, drain every recipient row and finalize the campaign.
        let report = exec.tick().await.expect("tick 1");
        assert_eq!(report.campaigns_started, 1);
        assert_eq!(report.recipients_sent, 3);
        assert_eq!(report.campaigns_completed, 1);
        let (status, sent_count) = campaign_status(&pool, campaign).await;
        assert_eq!(status, "sent", "no failures → sent");
        assert_eq!(sent_count, 3);
        let rows = recipient_statuses(&pool, campaign).await;
        assert_eq!(rows.len(), 3, "audience expanded");
        assert!(rows.iter().all(|(_, status)| status == "sent"));

        // Every recipient enqueued exactly one queued message + queue row,
        // with the idempotency key and campaign back-references.
        for email in &emails {
            let row: Option<(Uuid, Value)> = sqlx::query_as(
                "SELECT id, metadata FROM messages \
                 WHERE tenant_id = $1 AND to_emails = $2 AND status = 'queued'",
            )
            .bind(&tenant)
            .bind(serde_json::json!([email]))
            .fetch_optional(&pool)
            .await
            .expect("message lookup");
            let (message_id, metadata) = row.expect("one queued message per recipient");
            assert_eq!(metadata["source"], "campaigns");
            assert_eq!(metadata["campaign_id"], campaign.to_string());

            let queue: (String, Option<String>) = sqlx::query_as(
                "SELECT status, campaign_id::text FROM email_queue WHERE message_id = $1",
            )
            .bind(message_id)
            .fetch_one(&pool)
            .await
            .expect("queue row");
            assert_eq!(queue.0, "pending");
            assert_eq!(queue.1.as_deref(), Some(campaign.to_string().as_str()));

            let tracked: Option<Uuid> = sqlx::query_scalar(
                "SELECT message_id FROM campaign_recipients \
                 WHERE campaign_id = $1 AND email = $2",
            )
            .bind(campaign)
            .bind(email)
            .fetch_optional(&pool)
            .await
            .expect("backref lookup");
            assert_eq!(tracked, Some(message_id), "message back-reference set");
        }

        // Idempotency: a second tick finds no claimable work and changes
        // nothing — no double sends, no re-convergence.
        let report = exec.tick().await.expect("tick 2");
        assert_eq!(report.recipients_sent, 0);
        let (status, _) = campaign_status(&pool, campaign).await;
        assert_eq!(status, "sent");
        pool.close().await;
    }

    /// Suppressed recipients are terminal `suppressed`, never retried — and
    /// the campaign still converges `partial` with the rest `sent`.
    #[tokio::test]
    async fn suppression_is_terminal_and_yields_partial() {
        let Some(pool) = fresh_pool("campaigns_suppression", "suppression").await else {
            return;
        };
        let tenant = fresh_tenant("camp-supp");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        backend.suppress("suppressed@example.test");
        let exec = executor(&pool, backend);

        let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        let list = insert_list(&pool, &tenant).await;
        for (email, status) in [
            ("clean1@example.test", "active"),
            ("clean2@example.test", "subscribed"),
            ("suppressed@example.test", "active"),
        ] {
            let contact = insert_contact(&pool, &tenant, email, status).await;
            subscribe(&pool, list, contact).await;
        }
        sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
            .bind(campaign)
            .bind(serde_json::json!([list.to_string()]).to_string())
            .execute(&pool)
            .await
            .expect("attach list");

        // One tick: claim + expand + drain + finalize.
        let report = exec.tick().await.expect("pipeline tick");
        assert_eq!(report.recipients_suppressed, 1);
        assert_eq!(report.recipients_sent, 2);

        let (status, sent_count) = campaign_status(&pool, campaign).await;
        assert_eq!(status, "partial", "a suppressed recipient is a failure");
        assert_eq!(sent_count, 2);

        // A resend job must NOT requeue the suppressed row — only `failed`.
        sqlx::query(
            "INSERT INTO campaign_jobs (id, campaign_id, tenant_id, job_type, status) \
             VALUES ($1, $2, $3, 'resend', 'queued')",
        )
        .bind(Uuid::new_v4())
        .bind(campaign)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert job");
        // Move the campaign into `resending` like the API route does.
        sqlx::query("UPDATE campaigns SET status = 'resending' WHERE id = $1")
            .bind(campaign)
            .execute(&pool)
            .await
            .expect("resending");
        let report = exec.tick().await.expect("resend tick");
        assert_eq!(report.jobs_completed, 1);
        let rows = recipient_statuses(&pool, campaign).await;
        let suppressed_row = rows
            .iter()
            .find(|(email, _)| email == "suppressed@example.test")
            .expect("suppressed row present");
        assert_eq!(
            suppressed_row.1, "suppressed",
            "a resend must never retry a suppressed recipient"
        );
        pool.close().await;
    }

    /// A poison recipient (quota exceeded forever) does not block the batch:
    /// the other recipients still send, and the campaign carries the failure.
    #[tokio::test]
    async fn quota_deferred_recipients_stay_queued_and_batch_continues() {
        let Some(pool) = fresh_pool("campaigns_poison", "poison").await else {
            return;
        };
        let tenant = fresh_tenant("camp-poison");
        insert_tenant(&pool, &tenant).await;
        // Quota 1: exactly one recipient is admitted; the rest defer.
        let backend = Arc::new(FakeAdmission::new());
        backend.set_limit(1);
        let exec = executor(&pool, backend);

        let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        let list = insert_list(&pool, &tenant).await;
        for i in 0..3 {
            let contact = insert_contact(
                &pool,
                &tenant,
                &format!("poison-{i}@example.test"),
                "active",
            )
            .await;
            subscribe(&pool, list, contact).await;
        }
        sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
            .bind(campaign)
            .bind(serde_json::json!([list.to_string()]).to_string())
            .execute(&pool)
            .await
            .expect("attach list");

        // One tick: claim + expand + drain. Quota admits exactly one; the
        // rest defer without failing.
        let report = exec.tick().await.expect("pipeline tick");
        assert_eq!(report.recipients_sent, 1, "quota admits exactly one");
        assert_eq!(report.recipients_deferred, 2, "the rest defer, not fail");

        // The campaign is NOT finalized while rows are still queued.
        let (status, _) = campaign_status(&pool, campaign).await;
        assert_eq!(status, "sending");

        // Drain state is recoverable: rows are back to `queued` for the next
        // tick (their admission identity is stable — a later quota raise
        // admits them without double-billing).
        let (queued,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id = $1 AND status = 'queued'",
        )
        .bind(campaign)
        .fetch_one(&pool)
        .await
        .expect("queued count");
        assert_eq!(queued, 2);
        pool.close().await;
    }

    /// Resend jobs requeue ONLY failed recipients; sent recipients are never
    /// re-enqueued (idempotency key per (campaign, contact) closes that door
    /// even across a crashed tick).
    #[tokio::test]
    async fn resend_requeues_only_failed_rows_and_jobs_complete() {
        let Some(pool) = fresh_pool("campaigns_resend", "resend").await else {
            return;
        };
        let tenant = fresh_tenant("camp-resend");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend);

        let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        let list = insert_list(&pool, &tenant).await;
        let failed_email = "will-fail@example.test";
        for email in ["ok1@example.test", "ok2@example.test", failed_email] {
            let contact = insert_contact(&pool, &tenant, email, "active").await;
            subscribe(&pool, list, contact).await;
        }
        sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
            .bind(campaign)
            .bind(serde_json::json!([list.to_string()]).to_string())
            .execute(&pool)
            .await
            .expect("attach list");

        // One tick sends everyone and converges the campaign.
        exec.tick().await.expect("pipeline tick");
        let (status, sent_count) = campaign_status(&pool, campaign).await;
        assert_eq!(status, "sent");
        assert_eq!(sent_count, 3);

        // Poison ONE recipient: park it failed directly (simulating an
        // exhausted attempt budget), then run the API's resend flow.
        sqlx::query(
            "UPDATE campaign_recipients SET status = 'failed', error = 'injected' \
             WHERE campaign_id = $1 AND email = $2",
        )
        .bind(campaign)
        .bind(failed_email)
        .execute(&pool)
        .await
        .expect("inject failure");

        let job_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO campaign_jobs (id, campaign_id, tenant_id, job_type, status) \
             VALUES ($1, $2, $3, 'resend', 'queued')",
        )
        .bind(job_id)
        .bind(campaign)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert job");
        sqlx::query("UPDATE campaigns SET status = 'resending' WHERE id = $1")
            .bind(campaign)
            .execute(&pool)
            .await
            .expect("resending");

        // One tick processes the resend job AND drains the requeued row AND
        // re-converges the campaign.
        let report = exec.tick().await.expect("resend tick");
        assert_eq!(report.jobs_completed, 1);
        assert_eq!(report.recipients_sent, 1);

        let job: (String, Option<chrono::DateTime<Utc>>) =
            sqlx::query_as("SELECT status, completed_at FROM campaign_jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&pool)
                .await
                .expect("job row");
        assert_eq!(job.0, "completed");
        assert!(job.1.is_some(), "completed_at set");

        // Only the requeued row sent; the message count stays exactly 3 (the
        // failed row had no message; the ok rows are NOT re-sent).
        let (messages,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND metadata->>'campaign_id' = $2",
        )
        .bind(&tenant)
        .bind(campaign.to_string())
        .fetch_one(&pool)
        .await
        .expect("message count");
        assert_eq!(messages, 3, "resend never duplicates delivered recipients");
        let (status, sent_count) = campaign_status(&pool, campaign).await;
        assert_eq!(status, "sent");
        assert_eq!(sent_count, 3);
        pool.close().await;
    }

    /// Pause stops the drain mid-flight; resume continues and converges.
    /// The claimed-but-unsent rows stall under lease and are recovered.
    /// Pause stops the drain mid-flight; resume continues and converges.
    /// The bounded drain batch (2 of 3 recipients) leaves a row queued so the
    /// pause lands mid-drain, exactly like pausing a large live campaign.
    #[tokio::test]
    async fn pause_stops_the_drain_and_resume_finishes_it() {
        let Some(pool) = fresh_pool("campaigns_pause", "pause").await else {
            return;
        };
        let tenant = fresh_tenant("camp-pause");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        // Drain only 2 rows per tick, so the 3rd stays queued mid-drain.
        let exec = executor(&pool, backend).with_drain_batch_size(2);

        let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        let list = insert_list(&pool, &tenant).await;
        for i in 0..3 {
            let contact =
                insert_contact(&pool, &tenant, &format!("pause-{i}@example.test"), "active").await;
            subscribe(&pool, list, contact).await;
        }
        sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
            .bind(campaign)
            .bind(serde_json::json!([list.to_string()]).to_string())
            .execute(&pool)
            .await
            .expect("attach list");

        // Tick 1: claim + expand + drain the FIRST batch; one row is left
        // queued, so the campaign is NOT finalized.
        let report = exec.tick().await.expect("partial-drain tick");
        assert_eq!(report.recipients_sent, 2);
        let (status, _) = campaign_status(&pool, campaign).await;
        assert_eq!(status, "sending", "rows remain; not finalized yet");

        // Pause: no further row may be claimed.
        sqlx::query("UPDATE campaigns SET status = 'paused' WHERE id = $1")
            .bind(campaign)
            .execute(&pool)
            .await
            .expect("pause");
        let report = exec.tick().await.expect("paused tick");
        assert_eq!(
            report.recipients_sent, 0,
            "a paused campaign is not drained"
        );
        let (sent_rows,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id = $1 AND status = 'sent'",
        )
        .bind(campaign)
        .fetch_one(&pool)
        .await
        .expect("sent rows");
        assert_eq!(sent_rows, 2, "the pause froze the drain in place");

        // Resume → the drain finishes the remaining row and converges.
        sqlx::query("UPDATE campaigns SET status = 'sending' WHERE id = $1")
            .bind(campaign)
            .execute(&pool)
            .await
            .expect("resume");
        let report = exec.tick().await.expect("resumed tick");
        assert_eq!(report.recipients_sent, 1);
        let (status, sent_count) = campaign_status(&pool, campaign).await;
        assert_eq!(status, "sent");
        assert_eq!(sent_count, 3);
        pool.close().await;
    }

    /// Tenant isolation + ordering: a due campaign only ever expands its OWN
    /// tenant's list members, and earlier-scheduled campaigns claim first.
    #[tokio::test]
    async fn claims_are_tenant_scoped_and_due_order_holds() {
        let Some(pool) = fresh_pool("campaigns_isolation", "isolation").await else {
            return;
        };
        let tenant_a = fresh_tenant("camp-iso-a");
        let tenant_b = fresh_tenant("camp-iso-b");
        insert_tenant(&pool, &tenant_a).await;
        insert_tenant(&pool, &tenant_b).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend);

        let campaign_a =
            insert_ready_campaign(&pool, &tenant_a, "scheduled", Some(Utc::now())).await;
        let campaign_b =
            insert_ready_campaign(&pool, &tenant_b, "scheduled", Some(Utc::now())).await;
        let list_a = insert_list(&pool, &tenant_a).await;
        let contact_a = insert_contact(&pool, &tenant_a, "member-a@example.test", "active").await;
        subscribe(&pool, list_a, contact_a).await;
        // Same email on tenant B's roster must never leak into A's audience.
        let contact_b = insert_contact(&pool, &tenant_b, "member-a@example.test", "active").await;
        let _ = contact_b;
        sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
            .bind(campaign_a)
            .bind(serde_json::json!([list_a.to_string()]).to_string())
            .execute(&pool)
            .await
            .expect("attach list a");

        exec.tick().await.expect("tick");
        let rows_a = recipient_statuses(&pool, campaign_a).await;
        assert_eq!(rows_a.len(), 1, "tenant A expands only its own roster");
        let rows_b = recipient_statuses(&pool, campaign_b).await;
        assert!(
            rows_b.is_empty(),
            "tenant B has no audience rows (no lists)"
        );

        // A campaign scheduled in the FUTURE is not claimed.
        let future = insert_ready_campaign(
            &pool,
            &tenant_a,
            "scheduled",
            Some(Utc::now() + chrono::Duration::hours(1)),
        )
        .await;
        exec.tick().await.expect("tick");
        let (status, _) = campaign_status(&pool, future).await;
        assert_eq!(status, "scheduled", "future-due campaigns are untouched");
        pool.close().await;
    }

    /// A campaign missing its sender or template fails its rows honestly
    /// instead of crashing the batch or stalling forever.
    #[tokio::test]
    async fn missing_sender_or_template_fails_rows_honestly() {
        let Some(pool) = fresh_pool("campaigns_misconfig", "misconfig").await else {
            return;
        };
        let tenant = fresh_tenant("camp-misconf");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend);

        // Campaign with NO sender (template present).
        let no_sender = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        sqlx::query("UPDATE campaigns SET from_email = NULL WHERE id = $1")
            .bind(no_sender)
            .execute(&pool)
            .await
            .expect("drop sender");

        // Campaign with sender but an UNKNOWN template id (26-char ids are
        // the templates.id shape — the reference just doesn't resolve).
        let bad_template = apexmail_lib::id::generate_id("", 26);
        let domain = insert_domain(&pool, &tenant).await;
        let no_template = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO campaigns (id, tenant_id, name, subject, template_id, from_email, status, scheduled_at, list_ids) \
             VALUES ($1, $2, 'NoTemplate', 'S', $3, $4, 'scheduled', NOW(), '[]')",
        )
        .bind(no_template)
        .bind(&tenant)
        .bind(bad_template.to_string())
        .bind(format!("news@{domain}"))
        .execute(&pool)
        .await
        .expect("insert no-template campaign");

        // Give each campaign its OWN one-contact list so each drains exactly
        // one failing row (a shared list would put both contacts in both
        // audiences).
        for campaign in [no_sender, no_template] {
            let list = insert_list(&pool, &tenant).await;
            let contact = insert_contact(
                &pool,
                &tenant,
                &format!("m-{campaign}@example.test"),
                "active",
            )
            .await;
            subscribe(&pool, list, contact).await;
            sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
                .bind(campaign)
                .bind(serde_json::json!([list.to_string()]).to_string())
                .execute(&pool)
                .await
                .expect("attach list");
        }

        // One tick: claim + expand + drain (both rows fail honestly) +
        // finalize to `partial`.
        let report = exec.tick().await.expect("pipeline tick");
        assert_eq!(report.recipients_failed, 2, "both rows fail honestly");
        let rows = recipient_statuses(&pool, no_sender).await;
        assert!(rows.iter().all(|(_, s)| s == "failed"));
        let errors: Vec<String> =
            sqlx::query_scalar("SELECT error FROM campaign_recipients WHERE campaign_id = $1")
                .bind(no_sender)
                .fetch_all(&pool)
                .await
                .expect("errors");
        assert!(errors.iter().all(|e| e.contains("sender")), "{errors:?}");
        let (status, _) = campaign_status(&pool, no_sender).await;
        assert_eq!(status, "partial", "failures surface as a partial campaign");
        pool.close().await;
    }

    // -----------------------------------------------------------------------
    // A/B experiment execution (brief capabilities-3)
    // -----------------------------------------------------------------------

    /// Attach a configured A/B experiment: `n_arms` real tenant templates +
    /// the campaign's `ab_config`. Returns the config as stored.
    async fn attach_ab_experiment(
        pool: &PgPool,
        tenant: &str,
        campaign: Uuid,
        test_percentage: f64,
        n_arms: usize,
    ) -> Value {
        let mut arms = Vec::new();
        for index in 0..n_arms {
            let template = insert_template(pool, tenant).await;
            sqlx::query(
                "INSERT INTO campaign_ab_arms (campaign_id, arm_index, template_id) \
                 VALUES ($1, $2, $3)",
            )
            .bind(campaign)
            .bind(index as i32)
            .bind(&template)
            .execute(pool)
            .await
            .expect("insert arm");
            arms.push(serde_json::json!({"templateId": template}));
        }
        let config = serde_json::json!({
            "arms": arms,
            "testPercentage": test_percentage,
            "metric": "open",
            "waitMinutes": 60,
        });
        sqlx::query("UPDATE campaigns SET ab_config = $2 WHERE id = $1")
            .bind(campaign)
            .bind(&config)
            .execute(pool)
            .await
            .expect("attach ab config");
        config
    }

    /// Contacts with DETERMINISTIC ids (a fixed "seed"): contact N's id is
    /// `0x5eed…` + N, so the hash split is exactly reproducible across runs
    /// and assertion bounds are stable.
    async fn insert_seeded_contacts(
        pool: &PgPool,
        tenant: &str,
        label: &str,
        count: usize,
    ) -> Vec<(Uuid, String)> {
        // Deterministic per (label, index): the SAME label yields the same
        // ids (reproducible splits), different labels never collide.
        let label_bits = label
            .bytes()
            .fold(0u128, |acc, byte| acc.wrapping_mul(131).wrapping_add(byte.into()));
        let mut contacts = Vec::new();
        for index in 0..count {
            let id = Uuid::from_u128(
                0x5eed_0000_0000_0000_0000_0000_0000_0000
                    | ((label_bits & 0xffff_ffff) << 32)
                    | (index as u128 + 1),
            );
            let email = format!("{label}-{index}@ab-seed.test");
            sqlx::query(
                "INSERT INTO contacts (id, tenant_id, email, name, status) \
                 VALUES ($1, $2, $3, $4, 'active')",
            )
            .bind(id)
            .bind(tenant)
            .bind(&email)
            .bind(format!("Seed {index}"))
            .execute(pool)
            .await
            .expect("insert seeded contact");
            contacts.push((id, email));
        }
        contacts
    }

    fn due_campaign(
        tenant: &str,
        campaign: Uuid,
        list: Uuid,
        config: Option<&Value>,
    ) -> DueCampaign {
        DueCampaign {
            id: campaign,
            tenant_id: tenant.to_string(),
            list_ids: vec![list],
            exclude_list_ids: Vec::new(),
            segment_id: None,
            ab_config: config.cloned(),
        }
    }

    async fn ab_assignments(pool: &PgPool, campaign: Uuid) -> Vec<(String, String, i32)> {
        sqlx::query_as(
            "SELECT email, phase, COALESCE(arm_index, -1) FROM campaign_recipients \
             WHERE campaign_id = $1 ORDER BY email",
        )
        .bind(campaign)
        .fetch_all(pool)
        .await
        .expect("ab assignments")
    }

    /// The deterministic per-(experiment, recipient) hash split: the test
    /// sample lands inside the configured bound, every arm gets a share, a
    /// replay assigns the SAME arm, and insertion order is irrelevant.
    #[tokio::test]
    async fn ab_split_is_deterministic_per_recipient_and_meets_the_configured_bound() {
        let Some(pool) = fresh_pool("campaigns_ab_split", "ab_split").await else {
            return;
        };
        let tenant = fresh_tenant("camp-ab-split");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend);

        let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        let list = insert_list(&pool, &tenant).await;
        let config = attach_ab_experiment(&pool, &tenant, campaign, 0.2, 2).await;

        const RECIPIENTS: usize = 500;
        let contacts = insert_seeded_contacts(&pool, &tenant, "bound", RECIPIENTS).await;
        for (contact_id, email) in &contacts {
            sqlx::query(
                "INSERT INTO campaign_recipients (tenant_id, campaign_id, contact_id, email, status) \
                 VALUES ($1, $2, $3, $4, 'queued')",
            )
            .bind(&tenant)
            .bind(campaign)
            .bind(contact_id)
            .bind(email)
            .execute(&pool)
            .await
            .expect("seed recipient");
        }
        // The same expansion+split the pipeline runs, called directly so the
        // assertion is about the assignment, not about sends.
        let due = due_campaign(&tenant, campaign, list, Some(&config));
        exec.expand_audience(&due).await.expect("expand audience");
        exec.split_ab_recipients(campaign, due.ab_config.as_ref())
            .await
            .expect("split");

        let rows = ab_assignments(&pool, campaign).await;
        assert_eq!(rows.len(), RECIPIENTS);
        assert!(
            rows.iter().all(|(_, phase, _)| phase == "test" || phase == "holdout"),
            "every recipient is phased"
        );
        let test_count = rows.iter().filter(|(_, phase, _)| phase == "test").count();
        // p = 0.2 over 500 deterministic hashes: hidden inside ±5 points —
        // the assertion is exact for this fixed seed, not statistically
        // flaky.
        assert!(
            (75..=125).contains(&test_count),
            "test sample {test_count} outside the 15–25% bound for p=0.2/N=500"
        );
        let arm0 = rows.iter().filter(|(_, _, arm)| *arm == 0).count();
        let arm1 = rows.iter().filter(|(_, _, arm)| *arm == 1).count();
        assert_eq!(arm0 + arm1, test_count, "every test recipient has an arm");
        assert!(
            arm0 > 0 && arm1 > 0,
            "both arms receive a share (arm0={arm0}, arm1={arm1})"
        );
        let arm0_share = arm0 as f64 / test_count as f64;
        assert!(
            (0.35..=0.65).contains(&arm0_share),
            "arm0 share {arm0_share} outside the balanced bound"
        );
        // The bucket is persisted as assignment evidence.
        let missing_buckets: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id = $1 AND ab_bucket IS NULL",
        )
        .bind(campaign)
        .fetch_one(&pool)
        .await
        .expect("bucket count");
        assert_eq!(missing_buckets, 0, "every assignment persists its bucket");

        // Replay 1: resetting the phases and re-splitting the SAME audience
        // assigns the identical arm to every recipient.
        let before: Vec<(String, String, i32)> = rows.clone();
        sqlx::query(
            "UPDATE campaign_recipients SET phase = NULL, arm_index = NULL, ab_bucket = NULL \
             WHERE campaign_id = $1",
        )
        .bind(campaign)
        .execute(&pool)
        .await
        .expect("reset phases");
        exec.split_ab_recipients(campaign, due.ab_config.as_ref())
            .await
            .expect("re-split");
        assert_eq!(
            before,
            ab_assignments(&pool, campaign).await,
            "a replay assigns the same arm to the same recipient"
        );

        // Replay 2: rebuilding the audience in REVERSE insertion order still
        // assigns the same arm — the hash is keyed on (experiment,
        // contact), not on row order.
        sqlx::query("DELETE FROM campaign_recipients WHERE campaign_id = $1")
            .bind(campaign)
            .execute(&pool)
            .await
            .expect("clear recipients");
        for (contact_id, email) in contacts.iter().rev() {
            sqlx::query(
                "INSERT INTO campaign_recipients (tenant_id, campaign_id, contact_id, email, status) \
                 VALUES ($1, $2, $3, $4, 'queued')",
            )
            .bind(&tenant)
            .bind(campaign)
            .bind(contact_id)
            .bind(email)
            .execute(&pool)
            .await
            .expect("re-seed recipient");
        }
        exec.split_ab_recipients(campaign, due.ab_config.as_ref())
            .await
            .expect("re-split reversed");
        assert_eq!(
            before,
            ab_assignments(&pool, campaign).await,
            "insertion order must not change the assignment"
        );

        // Replay 3: the audience GREW (a resend re-expansion adds contacts).
        // The original recipients keep their arms — the assignment is keyed
        // on each recipient, never on the audience size or row rank.
        let extra = insert_seeded_contacts(&pool, &tenant, "bound-extra", 50).await;
        for (contact_id, email) in &extra {
            sqlx::query(
                "INSERT INTO campaign_recipients (tenant_id, campaign_id, contact_id, email, status) \
                 VALUES ($1, $2, $3, $4, 'queued')",
            )
            .bind(&tenant)
            .bind(campaign)
            .bind(contact_id)
            .bind(email)
            .execute(&pool)
            .await
            .expect("seed extra recipient");
        }
        sqlx::query(
            "UPDATE campaign_recipients SET phase = NULL, arm_index = NULL, ab_bucket = NULL \
             WHERE campaign_id = $1",
        )
        .bind(campaign)
        .execute(&pool)
        .await
        .expect("reset phases again");
        exec.split_ab_recipients(campaign, due.ab_config.as_ref())
            .await
            .expect("re-split with a grown audience");
        let after_growth: Vec<(String, String, i32)> = ab_assignments(&pool, campaign)
            .await
            .into_iter()
            .filter(|(email, _, _)| !email.contains("bound-extra"))
            .collect();
        assert_eq!(after_growth.len(), RECIPIENTS);
        assert_eq!(
            before, after_growth,
            "an audience that grows on resend must not re-shuffle existing arms"
        );
        pool.close().await;
    }

    /// The holdout receives NOTHING while the experiment runs: only `test`
    /// recipients are claimed and enqueued, and the campaign stays `sending`
    /// (held for the winner).
    #[tokio::test]
    async fn ab_holdout_receives_nothing_until_a_winner_is_declared() {
        let Some(pool) = fresh_pool("campaigns_ab_holdout", "ab_holdout").await else {
            return;
        };
        let tenant = fresh_tenant("camp-ab-hold");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend);

        let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        let list = insert_list(&pool, &tenant).await;
        attach_ab_experiment(&pool, &tenant, campaign, 0.2, 2).await;
        sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
            .bind(campaign)
            .bind(serde_json::json!([list.to_string()]).to_string())
            .execute(&pool)
            .await
            .expect("attach list");
        let contacts = insert_seeded_contacts(&pool, &tenant, "holdout", 60).await;
        for (contact_id, _email) in &contacts {
            sqlx::query(
                "INSERT INTO list_subscribers (list_id, contact_id, status) \
                 VALUES ($1, $2, 'active')",
            )
            .bind(list)
            .bind(contact_id)
            .execute(&pool)
            .await
            .expect("subscribe");
        }

        let report = exec.tick().await.expect("pipeline tick");
        assert_eq!(report.campaigns_started, 1);
        let rows = ab_assignments(&pool, campaign).await;
        let test_count = rows.iter().filter(|(_, phase, _)| phase == "test").count();
        let holdout_count = rows
            .iter()
            .filter(|(_, phase, _)| phase == "holdout")
            .count();
        assert!(test_count > 0 && holdout_count > 0, "split landed");
        assert_eq!(
            report.recipients_sent as usize, test_count,
            "only test recipients are enqueued"
        );

        // Every holdout row is still queued with no message; every enqueued
        // message carries the test phase + arm metadata.
        let holdout_messages: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM campaign_recipients \
             WHERE campaign_id = $1 AND phase = 'holdout' \
               AND (status <> 'queued' OR message_id IS NOT NULL)",
        )
        .bind(campaign)
        .fetch_one(&pool)
        .await
        .expect("holdout check");
        assert_eq!(holdout_messages, 0, "holdout receives nothing");
        let metas: Vec<Value> =
            sqlx::query_scalar("SELECT metadata FROM messages WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_all(&pool)
                .await
                .expect("message metadata");
        assert_eq!(metas.len(), test_count);
        assert!(
            metas.iter().all(|metadata| {
                metadata["ab_phase"] == "test" && metadata["ab_arm"].is_i64()
            }),
            "every test send carries its arm"
        );

        // The campaign is held: the experiment is not concluded.
        let (status, _) = campaign_status(&pool, campaign).await;
        assert_eq!(status, "sending", "campaign waits for the winner");
        pool.close().await;
    }

    /// Seed one arm's observed outcome: `trials` sent test recipients, each
    /// with a distinct message id, and `successes` of them carrying the
    /// metric event.
    async fn seed_arm_outcome(
        pool: &PgPool,
        tenant: &str,
        campaign: Uuid,
        arm: i32,
        label: &str,
        trials: usize,
        successes: usize,
    ) {
        let contacts = insert_seeded_contacts(pool, tenant, label, trials).await;
        for (index, (contact_id, email)) in contacts.iter().enumerate() {
            let message_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO campaign_recipients \
                 (tenant_id, campaign_id, contact_id, email, status, phase, arm_index, message_id) \
                 VALUES ($1, $2, $3, $4, 'sent', 'test', $5, $6)",
            )
            .bind(tenant)
            .bind(campaign)
            .bind(contact_id)
            .bind(email)
            .bind(arm)
            .bind(message_id)
            .execute(pool)
            .await
            .expect("seed test recipient");
            if index < successes {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, campaign_id, event_type, recipient, timestamp) \
                     VALUES ($1, $2, $3, $4, 'opened', $5, NOW() - INTERVAL '1 minute')",
                )
                .bind(format!("evt_{}", Uuid::new_v4().simple()))
                .bind(tenant)
                .bind(message_id.to_string())
                .bind(campaign.to_string())
                .bind(email)
                .execute(pool)
                .await
                .expect("seed metric event");
            }
        }
    }

    /// Open the experiment's test window: the split stamped the arms at
    /// `NOW()`, so a test that wants the evaluation to run backdates the
    /// window clock by two hours (past `waitMinutes = 60`).
    async fn backdate_ab_window(pool: &PgPool, campaign: Uuid) {
        sqlx::query(
            "UPDATE campaign_ab_arms SET updated_at = NOW() - INTERVAL '2 hours' \
             WHERE campaign_id = $1",
        )
        .bind(campaign)
        .execute(pool)
        .await
        .expect("backdate ab window");
    }

    async fn seed_holdout_recipients(
        pool: &PgPool,
        tenant: &str,
        campaign: Uuid,
        label: &str,
        count: usize,
    ) {
        let contacts = insert_seeded_contacts(pool, tenant, label, count).await;
        for (contact_id, email) in contacts {
            sqlx::query(
                "INSERT INTO campaign_recipients \
                 (tenant_id, campaign_id, contact_id, email, status, phase) \
                 VALUES ($1, $2, $3, $4, 'queued', 'holdout')",
            )
            .bind(tenant)
            .bind(campaign)
            .bind(contact_id)
            .bind(email)
            .execute(pool)
            .await
            .expect("seed holdout recipient");
        }
    }

    /// Below the minimum per-arm sample the rule REFUSES: no winner is
    /// recorded and the holdout stays held (the reason is surfaced by the
    /// experiment API, which runs the same rule).
    #[tokio::test]
    async fn ab_winner_is_refused_below_the_minimum_sample() {
        let Some(pool) = fresh_pool("campaigns_ab_below", "ab_below").await else {
            return;
        };
        let tenant = fresh_tenant("camp-ab-below");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend);

        let campaign = insert_ready_campaign(&pool, &tenant, "sending", None).await;
        attach_ab_experiment(&pool, &tenant, campaign, 0.2, 2).await;
        // 10 trials per arm — below the documented 30-trial floor — with a
        // huge apparent lead (3/10 vs 0/10).
        seed_arm_outcome(&pool, &tenant, campaign, 0, "small-a", 10, 3).await;
        seed_arm_outcome(&pool, &tenant, campaign, 1, "small-b", 10, 0).await;
        seed_holdout_recipients(&pool, &tenant, campaign, "small-h", 5).await;
        backdate_ab_window(&pool, campaign).await;

        exec.evaluate_ab_tests().await.expect("evaluate");

        let config: Value = sqlx::query_scalar("SELECT ab_config FROM campaigns WHERE id = $1")
            .bind(campaign)
            .fetch_one(&pool)
            .await
            .expect("ab config");
        assert!(
            config.get("winnerArm").is_none(),
            "no winner below the minimum sample: {config}"
        );
        let holdout_phases: Vec<String> = sqlx::query_scalar(
            "SELECT phase FROM campaign_recipients WHERE campaign_id = $1 AND email LIKE 'small-h-%'",
        )
        .bind(campaign)
        .fetch_all(&pool)
        .await
        .expect("holdout phases");
        assert!(
            holdout_phases.iter().all(|phase| phase == "holdout"),
            "the holdout stays held on a refusal"
        );
        pool.close().await;
    }

    /// Above the sample floor with a significant lead the rule DECLARES the
    /// winner: it is recorded with its provenance and the holdout is
    /// promoted onto that arm. A merely leading but non-significant
    /// difference still refuses.
    #[tokio::test]
    async fn ab_winner_is_declared_above_the_sample_with_the_documented_rule() {
        let Some(pool) = fresh_pool("campaigns_ab_winner", "ab_winner").await else {
            return;
        };
        let tenant = fresh_tenant("camp-ab-winner");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend);

        let campaign = insert_ready_campaign(&pool, &tenant, "sending", None).await;
        attach_ab_experiment(&pool, &tenant, campaign, 0.2, 2).await;
        // 30% vs 10% over 100 trials each: z ≈ 3.5 > 1.96.
        seed_arm_outcome(&pool, &tenant, campaign, 0, "big-a", 100, 30).await;
        seed_arm_outcome(&pool, &tenant, campaign, 1, "big-b", 100, 10).await;
        seed_holdout_recipients(&pool, &tenant, campaign, "big-h", 6).await;
        backdate_ab_window(&pool, campaign).await;

        exec.evaluate_ab_tests().await.expect("evaluate");

        let config: Value = sqlx::query_scalar("SELECT ab_config FROM campaigns WHERE id = $1")
            .bind(campaign)
            .fetch_one(&pool)
            .await
            .expect("ab config");
        assert_eq!(config["winnerArm"], 0, "arm 0 wins: {config}");
        assert_eq!(config["winnerSource"], "auto");
        assert_eq!(config["winnerMetric"], "opened");
        let z = config["winnerZ"].as_f64().expect("winner z recorded");
        assert!(z >= apexmail_lib::ab_testing::Z_CRITICAL, "z = {z}");
        let promoted: Vec<(String, i32)> = sqlx::query_as(
            "SELECT phase, arm_index FROM campaign_recipients \
             WHERE campaign_id = $1 AND email LIKE 'big-h-%' ORDER BY email",
        )
        .bind(campaign)
        .fetch_all(&pool)
        .await
        .expect("holdout phases");
        assert_eq!(promoted.len(), 6);
        assert!(
            promoted.iter().all(|(phase, arm)| phase == "winner" && *arm == 0),
            "the holdout is promoted onto the winning arm: {promoted:?}"
        );
        pool.close().await;
    }

    /// A leader that is merely ahead (not statistically significant) is
    /// refused: 20% vs 16% over 100 trials each is z ≈ 0.74.
    #[tokio::test]
    async fn ab_winner_is_refused_without_a_significant_leader() {
        let Some(pool) = fresh_pool("campaigns_ab_tie", "ab_tie").await else {
            return;
        };
        let tenant = fresh_tenant("camp-ab-tie");
        insert_tenant(&pool, &tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend);

        let campaign = insert_ready_campaign(&pool, &tenant, "sending", None).await;
        attach_ab_experiment(&pool, &tenant, campaign, 0.2, 2).await;
        seed_arm_outcome(&pool, &tenant, campaign, 0, "tie-a", 100, 20).await;
        seed_arm_outcome(&pool, &tenant, campaign, 1, "tie-b", 100, 16).await;
        seed_holdout_recipients(&pool, &tenant, campaign, "tie-h", 4).await;
        backdate_ab_window(&pool, campaign).await;

        exec.evaluate_ab_tests().await.expect("evaluate");

        let config: Value = sqlx::query_scalar("SELECT ab_config FROM campaigns WHERE id = $1")
            .bind(campaign)
            .fetch_one(&pool)
            .await
            .expect("ab config");
        assert!(
            config.get("winnerArm").is_none(),
            "a non-significant lead must not declare a winner: {config}"
        );
        let held: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM campaign_recipients \
             WHERE campaign_id = $1 AND email LIKE 'tie-h-%' AND phase = 'holdout'",
        )
        .bind(campaign)
        .fetch_one(&pool)
        .await
        .expect("holdout count");
        assert_eq!(held, 4);
        pool.close().await;
    }

    /// Wave G: `settings.sendTimeOptimization` is the documented Pro+ contract
    /// ("Schedule each recipient at their optimal engagement hour"). The drain
    /// must schedule the queue row at the recipient's next window (here a
    /// Tuesday 14:00 UTC profile for an offset-0 tenant), and the same
    /// address's events under ANOTHER tenant must not shift it. Without the
    /// setting, the queue row keeps scheduled_at NULL (immediate send).
    #[tokio::test]
    async fn send_time_optimization_schedules_the_recipient_window() {
        use chrono::Datelike as _;

        let Some(pool) = fresh_pool("campaigns_sto", "sto").await else {
            return;
        };
        let tenant = fresh_tenant("camp-sto");
        insert_tenant(&pool, &tenant).await;
        let other_tenant = fresh_tenant("camp-sto-other");
        insert_tenant(&pool, &other_tenant).await;
        let backend = Arc::new(FakeAdmission::new());
        let exec = executor(&pool, backend)
            .with_send_time_optimizer(SendTimeOptimizer::without_cache(pool.clone()));

        let email = format!("sto-{}@example.test", &Uuid::new_v4().simple().to_string()[..8]);

        // The recipient's profile under its own tenant: 8 opens at 14:00 UTC
        // on a Tuesday (2026-06-16). The SAME address under another tenant
        // carries 20 opens at 09:00 — a leak would make 09:00 dominant, so
        // the 14:00 assertion below doubles as the tenant-scoping proof.
        for (tenant_id, hour, count) in [
            (&tenant, 14, 8u32),
            (&other_tenant, 9, 20u32),
        ] {
            for _ in 0..count {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) \
                     VALUES ($1, $2, $3, 'opened', $4, \
                             TIMESTAMPTZ '2026-06-16 00:00:00+00' \
                                 + make_interval(hours => $5))",
                )
                .bind(Uuid::new_v4().to_string())
                .bind(tenant_id)
                .bind(Uuid::new_v4().to_string())
                .bind(&email)
                .bind(hour as i32)
                .execute(&pool)
                .await
                .expect("seed event");
            }
        }

        // STO campaign: due now, optimization on.
        let sto_campaign =
            insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        let sto_list = insert_list(&pool, &tenant).await;
        let contact = insert_contact(&pool, &tenant, &email, "active").await;
        subscribe(&pool, sto_list, contact).await;
        sqlx::query(
            "UPDATE campaigns SET list_ids = $2::jsonb, settings = $3::jsonb WHERE id = $1",
        )
        .bind(sto_campaign)
        .bind(serde_json::json!([sto_list.to_string()]).to_string())
        .bind(serde_json::json!({ "sendTimeOptimization": true }).to_string())
        .execute(&pool)
        .await
        .expect("attach STO settings");

        // Control campaign WITHOUT the setting → immediate scheduling.
        let plain_email =
            format!("plain-{}@example.test", &Uuid::new_v4().simple().to_string()[..8]);
        let plain_campaign =
            insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
        let plain_list = insert_list(&pool, &tenant).await;
        let plain_contact = insert_contact(&pool, &tenant, &plain_email, "active").await;
        subscribe(&pool, plain_list, plain_contact).await;
        sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
            .bind(plain_campaign)
            .bind(serde_json::json!([plain_list.to_string()]).to_string())
            .execute(&pool)
            .await
            .expect("attach plain list");

        let report = exec.tick().await.expect("STO tick");
        assert_eq!(report.recipients_sent, 2);

        // The optimized row carries the next Tuesday 14:00 UTC occurrence.
        let scheduled: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
            "SELECT eq.scheduled_at FROM email_queue eq \
             JOIN contacts c ON c.id = eq.contact_id \
             WHERE c.email = $1",
        )
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("optimized queue row");
        let scheduled = scheduled.expect("STO must set a scheduled window");
        assert!(
            scheduled > Utc::now(),
            "the window must be in the future: {scheduled}"
        );
        assert_eq!(
            scheduled.time(),
            chrono::NaiveTime::from_hms_opt(14, 0, 0).unwrap(),
            "profile peak at 14:00 UTC must be the scheduled local hour"
        );
        assert_eq!(
            scheduled.date_naive().weekday().num_days_from_monday(),
            1,
            "the profile's Tuesday peak must be the scheduled weekday ({scheduled})"
        );

        // messages.scheduled_at mirrors the queue's window.
        let message_scheduled: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
            "SELECT scheduled_at FROM messages WHERE tenant_id = $1 AND to_emails = $2",
        )
        .bind(&tenant)
        .bind(serde_json::json!([email]))
        .fetch_one(&pool)
        .await
        .expect("message row");
        assert_eq!(message_scheduled, Some(scheduled));

        // The control row is NOT delayed.
        let plain_scheduled: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
            "SELECT eq.scheduled_at FROM email_queue eq \
             JOIN contacts c ON c.id = eq.contact_id \
             WHERE c.email = $1",
        )
        .bind(&plain_email)
        .fetch_one(&pool)
        .await
        .expect("plain queue row");
        assert_eq!(plain_scheduled, None, "without STO the send is immediate");

        pool.close().await;
    }
}
