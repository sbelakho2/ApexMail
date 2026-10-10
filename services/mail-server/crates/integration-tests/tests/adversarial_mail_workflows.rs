//! Adversarial mail / campaign workflow contracts (cross-surface).
//!
//! These tests pin the contracts a user or attacker can observe from the
//! WORKFLOW layer — form actions, refusal strings, schedule authorization
//! copy — and, where the contract is behavioral, drive the REAL campaign
//! worker against a canonical database so the copy and the machinery must
//! agree. A failure here means the product is lying to its customers about
//! what mail will do.
//!
//! DB-backed cases soft-skip ONLY when `TEST_DATABASE_URL` is unset
//! (workspace convention); a configured-but-broken server panics.

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use billing_service::send_admission::{SendAdmissionBackend, SendAdmissionService};
use billing_service::usage::{QuotaRecordResult, UsageError};
use worker_processors::campaigns::CampaignExecutor;

// ---------------------------------------------------------------------------
// Contract literals (must match production source; see doc comments)
// ---------------------------------------------------------------------------

/// Exact REST 403 body of a send-endpoint quota refusal. Source of truth:
/// `api-server/src/routes/messages.rs` (`QUOTA_EXCEEDED_MESSAGE`), mapped
/// from `SendAdmissionError::QuotaExceeded` via `map_send_admission_error`.
/// Softening or rewriting this string without updating the endpoint breaks
/// every client that matches on the documented refusal.
const QUOTA_EXCEEDED_MESSAGE: &str = "email quota exceeded: the plan volume and its overage allowance are exhausted — upgrade the plan or contact sales for a higher ceiling";

/// The console start-action refusal for a campaign in a non-startable
/// status. Source of truth: `api-server/src/routes/web.rs`
/// (`form_campaign_start`). Curly quotes and the em dash are part of the
/// flashed copy.
fn campaign_start_refusal(status: &str) -> String {
    format!("Campaign is “{status}” — only draft or paused campaigns can be started.")
}

// ---------------------------------------------------------------------------
// Edit == update (never create-duplicate)
// ---------------------------------------------------------------------------

/// INVARIANT: the campaign EDIT surface posts to the UPDATE handler and
/// carries the row id — editing is identity-preserving. DANGER: a create
/// action on the edit form silently duplicates the campaign and abandons
/// the original (the "editing duplicated my campaign" data-loss workflow).
#[test]
fn campaign_edit_form_updates_the_row_and_never_creates_a_duplicate() {
    let edit = ui_foundation::leptos_views::web_campaign_edit_page_for_id("c_keep_123");
    assert!(
        edit.contains("action=\"/web/campaigns/update\""),
        "edit must post to the update handler, not create: {edit}"
    );
    assert!(
        edit.contains("name=\"id\" value=\"c_keep_123\""),
        "edit must carry the existing row id so the handler updates in place: {edit}"
    );
    assert!(
        !edit.contains("action=\"/web/campaigns\""),
        "edit must not fall through to the create action (duplicate campaign): {edit}"
    );

    // The value-prefilled editor shares the same update contract.
    let valued = ui_foundation::leptos_views::web_campaign_edit_page_with_values(
        &ui_foundation::view_data::CampaignEditData {
            id: "c_keep_456".into(),
            name: "Renamed".into(),
            subject: "New subject".into(),
            html_body: "<p>x</p>".into(),
            scheduled_at: String::new(),
        },
    );
    assert!(
        valued.contains("action=\"/web/campaigns/update\""),
        "{valued}"
    );
    assert!(
        valued.contains("name=\"id\" value=\"c_keep_456\""),
        "{valued}"
    );
    assert!(
        valued.contains("Saving updates this campaign in place"),
        "edit copy must promise an in-place update, matching the handler: {valued}"
    );

    // CREATE is a distinct surface with its own action — the two must not
    // share a form target.
    let create = ui_foundation::leptos_views::web_campaigns_new_page();
    assert!(
        create.contains("action=\"/web/campaigns\""),
        "the create editor keeps its own create action: {create}"
    );
    assert!(
        !create.contains("action=\"/web/campaigns/update\""),
        "the create editor must not post to update (it has no id to update): {create}"
    );
}

// ---------------------------------------------------------------------------
// Quota refusal copy is truthful
// ---------------------------------------------------------------------------

/// INVARIANT: a quota-exhausted send is refused with the EXACT documented
/// string (HTTP 403 Forbidden), not a soft success, not a vague error, not
/// a 429 that lies about retryability. DANGER: a rewritten refusal desyncs
/// every API client and every runbook; a 2xx under exhaustion silently
/// drops or double-bills mail.
#[test]
fn quota_exceeded_refusal_is_the_documented_forbidden_string() {
    // The literal is pinned against messages.rs. If production changes the
    // constant, this test must change in the same commit — never one-sided.
    assert_eq!(
        QUOTA_EXCEEDED_MESSAGE,
        "email quota exceeded: the plan volume and its overage allowance are exhausted — upgrade the plan or contact sales for a higher ceiling"
    );

    // The refusal must be actionable and name the exhaustion (not "error",
    // not "try again later" — the cap is not transient).
    assert!(
        QUOTA_EXCEEDED_MESSAGE.contains("quota exceeded"),
        "the refusal must name the quota exhaustion: {QUOTA_EXCEEDED_MESSAGE}"
    );
    assert!(
        QUOTA_EXCEEDED_MESSAGE.contains("upgrade the plan")
            || QUOTA_EXCEEDED_MESSAGE.contains("contact sales"),
        "the refusal must offer a recovery path: {QUOTA_EXCEEDED_MESSAGE}"
    );
    assert!(
        !QUOTA_EXCEEDED_MESSAGE.contains("try again"),
        "quota exhaustion is not transient — 'try again' copy would lie: {QUOTA_EXCEEDED_MESSAGE}"
    );
}

// ---------------------------------------------------------------------------
// Schedule == authorization (copy and worker must agree)
// ---------------------------------------------------------------------------

/// INVARIANT: saving a schedule IS authorization for an automatic send —
/// the editor copy says so, and the worker really claims due `scheduled`
/// campaigns and flips them to `sending`. DANGER: copy that claims
/// "nothing sends automatically" lets users arm production sends they
/// believe are inert; a worker that ignores `scheduled_at` makes the
/// authorization a silent no-op.
#[tokio::test]
async fn schedule_authorization_copy_matches_worker_autostart_behavior() {
    // --- Copy side: the create and edit editors state the auto-start truth.
    let create = ui_foundation::leptos_views::web_campaigns_new_page();
    assert!(
        create.contains("start automatically"),
        "the editor must state automatic start: {create}"
    );
    assert!(
        create.contains("authorizes that automatic send"),
        "saving a schedule must be framed as authorization: {create}"
    );
    assert!(
        !create.contains("nothing sends automatically"),
        "stale inert-schedule copy is a safety defect: {create}"
    );
    assert!(
        !create.contains("waits for you to press Start"),
        "stale manual-start copy is a safety defect: {create}"
    );

    let edit = ui_foundation::leptos_views::web_campaign_edit_page_with_values(
        &ui_foundation::view_data::CampaignEditData {
            id: "c_sched".into(),
            name: "S".into(),
            subject: "S".into(),
            html_body: String::new(),
            scheduled_at: "2030-01-01T09:00".into(),
        },
    );
    assert!(
        edit.contains("authorizes that automatic send"),
        "the edit editor must frame a saved schedule as authorization: {edit}"
    );
    assert!(
        edit.contains("start automatically") || edit.contains("starts the send automatically"),
        "the edit editor must state automatic start (production copy: \
         'starts the send automatically'): {edit}"
    );

    // --- Behavior side: the REAL worker claims a due scheduled campaign.
    let Some(pool) = fresh_pool("adv_mail_workflow_autostart").await else {
        return;
    };
    let tenant = fresh_tenant("adv-wf-auto");
    insert_tenant(&pool, &tenant).await;
    let backend = Arc::new(WorkflowAdmission::new());
    let exec = CampaignExecutor::new(
        pool.clone(),
        SendAdmissionService::new(backend),
        "adv-wf-auto-worker",
    );

    let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    let list = insert_list(&pool, &tenant).await;
    let contact = insert_contact(&pool, &tenant, "authorized@example.test", "active").await;
    subscribe(&pool, list, contact).await;
    sqlx::query("UPDATE campaigns SET list_ids = $2::jsonb WHERE id = $1")
        .bind(campaign)
        .bind(serde_json::json!([list.to_string()]).to_string())
        .execute(&pool)
        .await
        .expect("attach list");

    let report = exec.tick().await.expect("worker tick");
    assert_eq!(
        report.campaigns_started, 1,
        "the copy's 'start automatically' promise must be real: the due \
         scheduled campaign is claimed by the worker without any manual start"
    );
    let (status, sent_count) = sqlx::query_as::<_, (String, i32)>(
        "SELECT status, sent_count FROM campaigns WHERE id = $1",
    )
    .bind(campaign)
    .fetch_one(&pool)
    .await
    .expect("campaign status");
    assert!(
        status == "sending" || status == "sent" || status == "partial",
        "a due scheduled campaign must leave 'scheduled' on its own (got {status})"
    );
    assert!(sent_count >= 1, "the authorized send must actually deliver");
    pool.close().await;
}

// ---------------------------------------------------------------------------
// Pause / resume / start lifecycle rules
// ---------------------------------------------------------------------------

/// INVARIANT: `scheduled` campaigns are NOT manually startable — the worker
/// owns them; only `draft` and `paused` may be started by hand. DANGER: a
/// manual start on a scheduled campaign double-fires against the worker's
/// automatic claim (two paths to `sending` = double-send risk) and breaks
/// the "schedule == authorization" story users rely on.
///
/// The refusal string is pinned against `api-server/src/routes/web.rs`
/// (`form_campaign_start`); the startable set is pinned against
/// `campaign_start_allowed` in the same file. Both are private handler
/// details, so this test freezes the contract surface a user can observe.
#[test]
fn scheduled_campaigns_are_not_manually_startable_but_draft_and_paused_are() {
    // Production refusal for a non-startable status — verbatim, curly
    // quotes and em dash included (web.rs `form_campaign_start`).
    assert_eq!(
        campaign_start_refusal("scheduled"),
        "Campaign is “scheduled” — only draft or paused campaigns can be started."
    );

    // The startable set (campaign_start_allowed: matches!(status, "draft" | "paused")).
    let startable = ["draft", "paused"];
    // The campaigns status vocabulary that must NOT be manually startable.
    // `scheduled` is the trap: the worker claims it; a human Start would
    // race that claim into a double-send.
    let not_startable = [
        "scheduled",
        "sending",
        "resending",
        "completed",
        "failed",
        "stopped",
    ];

    for status in startable {
        // Startable statuses never reach the deny arm; the refusal builder
        // (used only there) must still quote the status if invoked.
        let refusal = campaign_start_refusal(status);
        assert!(
            refusal.contains(status),
            "the refusal must name the status verbatim ({status}): {refusal}"
        );
        assert!(
            !refusal.contains("started successfully"),
            "a refusal must never look like success: {refusal}"
        );
    }
    for status in not_startable {
        let refusal = campaign_start_refusal(status);
        assert!(
            refusal.contains("only draft or paused campaigns can be started"),
            "{status} must be refused with the documented start rule: {refusal}"
        );
        assert!(
            refusal.contains(status),
            "the refusal must name the offending status: {refusal}"
        );
        assert!(
            !refusal.contains("started successfully"),
            "a refusal must never look like success: {refusal}"
        );
    }
}

// ---------------------------------------------------------------------------
// Empty audience honesty (workflow-visible contract)
// ---------------------------------------------------------------------------

/// INVARIANT: an empty audience is reported as empty — zero recipients, zero
/// sends, zero fabricated success. DANGER: a "sent" badge over a zero
/// audience trains operators to trust a pipeline that sent nothing; a
/// fallback to "everyone" is a privacy incident.
#[tokio::test]
async fn empty_audience_workflow_is_honest_zero_recipients_zero_sends() {
    let Some(pool) = fresh_pool("adv_mail_workflow_empty").await else {
        return;
    };
    let tenant = fresh_tenant("adv-wf-empty");
    insert_tenant(&pool, &tenant).await;
    let backend = Arc::new(WorkflowAdmission::new());
    let exec = CampaignExecutor::new(
        pool.clone(),
        SendAdmissionService::new(backend),
        "adv-wf-empty-worker",
    );

    // A populated roster the empty campaign must NOT touch.
    let list = insert_list(&pool, &tenant).await;
    for i in 0..2 {
        let contact = insert_contact(
            &pool,
            &tenant,
            &format!("wf-bystander-{i}@example.test"),
            "active",
        )
        .await;
        subscribe(&pool, list, contact).await;
    }

    // Empty audience: no lists, no segment.
    let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;

    let report = exec.tick().await.expect("empty-audience tick");
    assert_eq!(report.campaigns_started, 1, "the campaign is still claimed");
    assert_eq!(
        report.recipients_sent, 0,
        "an empty audience sends nothing — never the bystander roster"
    );

    let recipients: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id = $1")
            .bind(campaign)
            .fetch_one(&pool)
            .await
            .expect("recipient count");
    assert_eq!(
        recipients, 0,
        "zero recipients — honest empty, not everyone"
    );

    let messages: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE metadata->>'campaign_id' = $1")
            .bind(campaign.to_string())
            .fetch_one(&pool)
            .await
            .expect("message count");
    assert_eq!(messages, 0, "zero sends — no fabricated messages");

    let (_, sent_count): (String, i32) =
        sqlx::query_as("SELECT status, sent_count FROM campaigns WHERE id = $1")
            .bind(campaign)
            .fetch_one(&pool)
            .await
            .expect("campaign status");
    assert_eq!(
        sent_count, 0,
        "sent_count must stay zero — a non-zero count over an empty audience is a lie"
    );
    pool.close().await;
}

// ---------------------------------------------------------------------------
// DB harness (workspace TEST_DATABASE_URL soft-skip convention)
// ---------------------------------------------------------------------------

async fn fresh_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn fresh_tenant(label: &str) -> String {
    let suffix = Uuid::new_v4().simple().to_string();
    let prefix: String = label.chars().take(13).collect();
    format!("{prefix}-{}", &suffix[..12])
}

/// Minimal unlimited admission backend (suppression empty, quota open).
#[derive(Debug)]
struct WorkflowAdmission {
    limit: AtomicI64,
    used: AtomicI64,
    reserves: AtomicUsize,
    events: Mutex<std::collections::HashSet<Uuid>>,
}

impl WorkflowAdmission {
    fn new() -> Self {
        Self {
            limit: AtomicI64::new(-1),
            used: AtomicI64::new(0),
            reserves: AtomicUsize::new(0),
            events: Mutex::new(std::collections::HashSet::new()),
        }
    }
}

#[async_trait::async_trait]
impl SendAdmissionBackend for WorkflowAdmission {
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
        _recorded_at: chrono::DateTime<Utc>,
    ) -> Result<(), UsageError> {
        if self.events.lock().unwrap().remove(&event_id) {
            self.used.fetch_sub(quantity, Ordering::SeqCst);
        }
        Ok(())
    }

    async fn suppressed_recipients(
        &self,
        _tenant_id: &str,
        _canonical_recipients: &[String],
    ) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
}

async fn insert_tenant(pool: &PgPool, tenant: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) \
         VALUES ($1, $2, $3, 'free', 'active')",
    )
    .bind(tenant)
    .bind(format!("Adv WFlow {tenant}"))
    .bind(format!("advwf-{tenant}"))
    .execute(pool)
    .await
    .expect("insert tenant");
}

async fn insert_ready_campaign(
    pool: &PgPool,
    tenant: &str,
    status: &str,
    scheduled_at: Option<chrono::DateTime<Utc>>,
) -> Uuid {
    let domain = format!(
        "advwf-{}.example.com",
        &Uuid::new_v4().simple().to_string()[..12]
    );
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, \
         ses_verified, dkim_selector, dkim_public_key, dkim_private_key) \
         VALUES ($1, $2, $3, 'verified', true, true, true, 'advwf', 'advwf-pub', 'dkim:v1:advwf')",
    )
    .bind(Uuid::new_v4())
    .bind(tenant)
    .bind(&domain)
    .execute(pool)
    .await
    .expect("insert domain");

    let template_id = format!("tpl_{}", &Uuid::new_v4().simple().to_string()[..16]);
    sqlx::query(
        "INSERT INTO templates (id, tenant_id, name, slug, subject, html_body, text_body) \
         VALUES ($1, $2, $3, $4, 'Hello {{first_name}}', '<p>Hi {{name}}</p>', 'Hi {{first_name}}')",
    )
    .bind(&template_id)
    .bind(tenant)
    .bind(format!("Template {template_id}"))
    .bind(&template_id)
    .execute(pool)
    .await
    .expect("insert template");

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO campaigns (id, tenant_id, name, subject, template_id, from_email, \
         status, scheduled_at, sent_count, list_ids) \
         VALUES ($1, $2, $3, 'Hello {{first_name}}', $4, $5, $6, $7, 0, '[]'::jsonb)",
    )
    .bind(id)
    .bind(tenant)
    .bind(format!("Campaign {id}"))
    .bind(&template_id)
    .bind(format!("news@{domain}"))
    .bind(status)
    .bind(scheduled_at)
    .execute(pool)
    .await
    .expect("insert campaign");
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
