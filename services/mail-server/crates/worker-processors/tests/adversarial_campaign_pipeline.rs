//! Adversarial DB-backed tests for the campaign send pipeline
//! (`worker_processors::campaigns::CampaignExecutor`).
//!
//! These tests pin the DANGEROUS invariants of the mail pipeline — the ones
//! whose failure means real customer harm (double-sends, suppressed mail
//! leaving the building, fabricated "sent" counts, cross-worker races).
//! Expectations are copied from the production source (`src/campaigns.rs`),
//! not from a desired redesign: if a test disagrees with the code, one of
//! them is lying.
//!
//! Every test provisions its own canonical database through the production
//! migrator ([`migrator::test_support::fresh_canonical_pool`]): a soft skip
//! is allowed ONLY when `TEST_DATABASE_URL` is unset; a configured
//! environment that cannot provision panics (audit F01).
//!
//! Admission runs through the shared `SendAdmissionService` with the same
//! deterministic in-memory backend shape the automations executor tests use.

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use billing_service::send_admission::{SendAdmissionBackend, SendAdmissionService};
use billing_service::usage::{QuotaRecordResult, UsageError};
use worker_processors::campaigns::CampaignExecutor;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Fresh canonical database per test (soft-skip only when TEST_DATABASE_URL
/// is unset; configured-but-broken panics — never a silent skip).
async fn fresh_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// Unique per-run tenant id, capped at 26 chars (`VARCHAR(26)`).
fn fresh_tenant(label: &str) -> String {
    let suffix = Uuid::new_v4().simple().to_string();
    let prefix: String = label.chars().take(13).collect();
    format!("{prefix}-{}", &suffix[..12])
}

/// In-memory admission backend: quota limit, suppression set, usage-event
/// de-duplication. Suppressed emails are matched after canonicalization
/// (lowercased/trimmed), exactly like the production backend.
#[derive(Debug)]
struct FakeAdmission {
    limit: AtomicI64,
    used: AtomicI64,
    reserves: AtomicUsize,
    events: Mutex<std::collections::HashSet<Uuid>>,
    suppressed: Mutex<Vec<String>>,
}

impl FakeAdmission {
    fn new() -> Self {
        Self {
            limit: AtomicI64::new(-1),
            used: AtomicI64::new(0),
            reserves: AtomicUsize::new(0),
            events: Mutex::new(std::collections::HashSet::new()),
            suppressed: Mutex::new(Vec::new()),
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
        _recorded_at: chrono::DateTime<Utc>,
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

fn executor(pool: &PgPool, backend: Arc<FakeAdmission>, worker_id: &str) -> CampaignExecutor {
    CampaignExecutor::new(pool.clone(), SendAdmissionService::new(backend), worker_id)
        .with_batch_size(50)
        .with_drain_batch_size(50)
}

async fn insert_tenant(pool: &PgPool, tenant: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) \
         VALUES ($1, $2, $3, 'free', 'active')",
    )
    .bind(tenant)
    .bind(format!("Adv Camp {tenant}"))
    .bind(format!("advcamp-{tenant}"))
    .execute(pool)
    .await
    .expect("insert tenant");
}

/// Verified, DKIM-ready sender domain (the readiness contract the enqueue
/// transaction enforces).
async fn insert_domain(pool: &PgPool, tenant: &str) -> String {
    let domain = format!(
        "advcamp-{}.example.com",
        &Uuid::new_v4().simple().to_string()[..12]
    );
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, \
         ses_verified, dkim_selector, dkim_public_key, dkim_private_key) \
         VALUES ($1, $2, $3, 'verified', true, true, true, 'adv-selector', 'adv-public', \
                 'dkim:v1:adv-test')",
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
         VALUES ($1, $2, $3, $4, 'Hello {{first_name}}', '<p>Hi {{name}}</p>', 'Hi {{first_name}}')",
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
    insert_contact_with_tags(pool, tenant, email, status, serde_json::json!([])).await
}

async fn insert_contact_with_tags(
    pool: &PgPool,
    tenant: &str,
    email: &str,
    status: &str,
    tags: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, email, name, status, tags) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(tenant)
    .bind(email)
    .bind(email.split('@').next().unwrap_or("Contact"))
    .bind(status)
    .bind(tags)
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

/// A campaign with a ready sender + template (audience attached separately).
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
         VALUES ($1, $2, $3, 'Hello {{first_name}}', $4, $5, $6, $7, 0, '[]'::jsonb)",
    )
    .bind(id)
    .bind(tenant)
    .bind(format!("Campaign {id}"))
    .bind(&template_id)
    .bind(&from)
    .bind(status)
    .bind(scheduled_at)
    .execute(pool)
    .await
    .expect("insert campaign");
    id
}

async fn attach_lists(pool: &PgPool, campaign: Uuid, include: &[Uuid], exclude: &[Uuid]) {
    let include_json = serde_json::Value::Array(
        include
            .iter()
            .map(|u| serde_json::Value::String(u.to_string()))
            .collect(),
    );
    let exclude_json = serde_json::Value::Array(
        exclude
            .iter()
            .map(|u| serde_json::Value::String(u.to_string()))
            .collect(),
    );
    sqlx::query(
        "UPDATE campaigns SET list_ids = $2::jsonb, exclude_list_ids = $3::jsonb WHERE id = $1",
    )
    .bind(campaign)
    .bind(include_json)
    .bind(exclude_json)
    .execute(pool)
    .await
    .expect("attach lists");
}

async fn attach_segment(pool: &PgPool, campaign: Uuid, segment: Uuid) {
    sqlx::query("UPDATE campaigns SET segment_id = $2 WHERE id = $1")
        .bind(campaign)
        .bind(segment)
        .execute(pool)
        .await
        .expect("attach segment");
}

async fn insert_segment(
    pool: &PgPool,
    tenant: &str,
    list_ids: &[Uuid],
    exclude_list_ids: &[Uuid],
    match_rules: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    let ids_json = |ids: &[Uuid]| {
        serde_json::Value::Array(
            ids.iter()
                .map(|u| serde_json::Value::String(u.to_string()))
                .collect(),
        )
    };
    sqlx::query(
        "INSERT INTO segments (id, tenant_id, name, list_ids, exclude_list_ids, match) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(tenant)
    .bind(format!("Segment {id}"))
    .bind(ids_json(list_ids))
    .bind(ids_json(exclude_list_ids))
    .bind(match_rules)
    .execute(pool)
    .await
    .expect("insert segment");
    id
}

async fn campaign_status(pool: &PgPool, campaign_id: Uuid) -> (String, i32) {
    sqlx::query_as("SELECT status, sent_count FROM campaigns WHERE id = $1")
        .bind(campaign_id)
        .fetch_one(pool)
        .await
        .expect("campaign status")
}

async fn recipient_emails(pool: &PgPool, campaign_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT email FROM campaign_recipients WHERE campaign_id = $1 ORDER BY email",
    )
    .bind(campaign_id)
    .fetch_all(pool)
    .await
    .expect("recipient emails")
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

async fn message_count_for(pool: &PgPool, tenant: &str, campaign: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages \
         WHERE tenant_id = $1 AND metadata->>'campaign_id' = $2",
    )
    .bind(tenant)
    .bind(campaign.to_string())
    .fetch_one(pool)
    .await
    .expect("message count")
}

async fn message_count_to(pool: &PgPool, tenant: &str, email: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages \
         WHERE tenant_id = $1 AND to_emails = $2::jsonb",
    )
    .bind(tenant)
    .bind(serde_json::json!([email]).to_string())
    .fetch_one(pool)
    .await
    .expect("per-recipient message count")
}

// ---------------------------------------------------------------------------
// Claim / schedule authorization
// ---------------------------------------------------------------------------

/// INVARIANT: a due `scheduled` campaign is CLAIMED and left `sending`, never
/// parked back in `scheduled`. DANGER: if the claim leaves the row
/// `scheduled`, the user's "save schedule == authorize automatic send"
/// promise is a lie and the campaign never starts; if the claim never flips
/// the status, two later ticks can claim it again and double-send.
///
/// The intermediate state is observed by hard-stopping quota at zero: every
/// recipient defers, so the tick ends with the campaign claimed-but-draining
/// (`sending`) instead of converging.
#[tokio::test]
async fn due_scheduled_campaign_is_claimed_to_sending_not_left_scheduled() {
    let Some(pool) = fresh_pool("adv_due_claimed_sending").await else {
        return;
    };
    let tenant = fresh_tenant("adv-claim");
    insert_tenant(&pool, &tenant).await;
    let backend = Arc::new(FakeAdmission::new());
    // Hard-stop: nothing may leave, so we can see the post-claim state.
    backend.set_limit(0);
    let exec = executor(&pool, backend.clone(), "adv-claim-worker");

    let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    let list = insert_list(&pool, &tenant).await;
    for i in 0..2 {
        let contact =
            insert_contact(&pool, &tenant, &format!("claim-{i}@example.test"), "active").await;
        subscribe(&pool, list, contact).await;
    }
    attach_lists(&pool, campaign, &[list], &[]).await;

    let report = exec.tick().await.expect("claim tick");
    assert_eq!(
        report.campaigns_started, 1,
        "the due campaign must be claimed exactly once"
    );

    let (status, sent_count) = campaign_status(&pool, campaign).await;
    assert_eq!(
        status, "sending",
        "claim must flip scheduled → sending; leaving it 'scheduled' means \
         the worker will claim it again every tick (double-send risk) or \
         never progress (silent stall)"
    );
    assert_ne!(
        status, "scheduled",
        "a due campaign must never stay scheduled after a tick"
    );
    assert_eq!(sent_count, 0, "nothing admitted yet — no fabricated count");

    // Audience expanded at claim time; every row is still honest (queued).
    let rows = recipient_statuses(&pool, campaign).await;
    assert_eq!(rows.len(), 2, "claim expands the audience");
    assert!(
        rows.iter().all(|(_, s)| s == "queued"),
        "quota hard-stop defers, never marks sent/failed: {rows:?}"
    );
    assert_eq!(
        message_count_for(&pool, &tenant, campaign).await,
        0,
        "a deferred recipient must never be enqueued"
    );
    pool.close().await;
}

/// INVARIANT: a campaign whose `scheduled_at` is still in the future is
/// untouched by every tick. DANGER: claiming early fires production mail
/// hours/days before the customer authorized it — a silent, irreversible
/// breach of the schedule==authorization contract.
#[tokio::test]
async fn future_due_scheduled_campaign_is_untouched() {
    let Some(pool) = fresh_pool("adv_future_untouched").await else {
        return;
    };
    let tenant = fresh_tenant("adv-future");
    insert_tenant(&pool, &tenant).await;
    let backend = Arc::new(FakeAdmission::new());
    let exec = executor(&pool, backend, "adv-future-worker");

    let due = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    let future = insert_ready_campaign(
        &pool,
        &tenant,
        "scheduled",
        Some(Utc::now() + chrono::Duration::hours(2)),
    )
    .await;
    let list = insert_list(&pool, &tenant).await;
    let contact = insert_contact(&pool, &tenant, "future@example.test", "active").await;
    subscribe(&pool, list, contact).await;
    attach_lists(&pool, due, &[list], &[]).await;
    attach_lists(&pool, future, &[list], &[]).await;

    let report = exec.tick().await.expect("tick");
    assert_eq!(report.campaigns_started, 1, "only the due campaign claims");

    let (future_status, _) = campaign_status(&pool, future).await;
    assert_eq!(
        future_status, "scheduled",
        "a future-due campaign must stay scheduled — claiming it early \
         sends mail before the customer's authorized time"
    );
    assert!(
        recipient_emails(&pool, future).await.is_empty(),
        "a future campaign must not even expand its audience yet"
    );
    assert_eq!(
        message_count_for(&pool, &tenant, future).await,
        0,
        "a future campaign must enqueue nothing"
    );

    // Repeated ticks keep it inert.
    for _ in 0..2 {
        let report = exec.tick().await.expect("repeat tick");
        assert_eq!(report.campaigns_started, 0);
    }
    let (future_status, _) = campaign_status(&pool, future).await;
    assert_eq!(future_status, "scheduled");
    pool.close().await;
}

// ---------------------------------------------------------------------------
// Concurrency: SKIP LOCKED / lease
// ---------------------------------------------------------------------------

/// INVARIANT: two workers racing the same due campaign cannot both claim it,
/// and two workers draining the same audience cannot both enqueue the same
/// recipient (`FOR UPDATE SKIP LOCKED` + the per-(campaign, contact)
/// idempotency key). DANGER: a double claim is a double-send to every
/// subscriber — the single most expensive bug a mail pipeline can ship.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_workers_cannot_double_claim_or_double_send() {
    let Some(pool) = fresh_pool("adv_double_claim").await else {
        return;
    };
    let tenant = fresh_tenant("adv-race");
    insert_tenant(&pool, &tenant).await;
    let backend = Arc::new(FakeAdmission::new());
    let worker_a = executor(&pool, backend.clone(), "adv-race-a");
    let worker_b = executor(&pool, backend.clone(), "adv-race-b");

    let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    let list = insert_list(&pool, &tenant).await;
    let mut emails = Vec::new();
    for i in 0..6 {
        let email = format!(
            "race-{i}-{}@example.test",
            &Uuid::new_v4().simple().to_string()[..6]
        );
        let contact = insert_contact(&pool, &tenant, &email, "active").await;
        subscribe(&pool, list, contact).await;
        emails.push(email);
    }
    attach_lists(&pool, campaign, &[list], &[]).await;

    // Both workers tick the SAME work at the same time.
    let (a, b) = tokio::join!(worker_a.tick(), worker_b.tick());
    let a = a.expect("worker A tick");
    let b = b.expect("worker B tick");

    assert_eq!(
        a.campaigns_started + b.campaigns_started,
        1,
        "SKIP LOCKED must let exactly one worker claim the due campaign \
         (A={}, B={})",
        a.campaigns_started,
        b.campaigns_started
    );
    assert_eq!(
        a.recipients_sent + b.recipients_sent,
        emails.len() as u64,
        "every recipient is sent exactly once across both workers (A={}, B={})",
        a.recipients_sent,
        b.recipients_sent
    );

    for email in &emails {
        let count = message_count_to(&pool, &tenant, email).await;
        assert_eq!(
            count, 1,
            "recipient {email} must have exactly one enqueued message, not one per worker"
        );
    }
    assert_eq!(
        message_count_for(&pool, &tenant, campaign).await,
        emails.len() as i64,
        "the campaign's total messages must equal its audience, never 2×"
    );

    // Every recipient row is terminal after both ticks (neither left a row
    // half-claimed); the campaign may still be `sending` here because the
    // two finalizes can each see the other's in-flight lease and skip — the
    // FOLLOW-UP tick must be the one that converges it.
    let rows = recipient_statuses(&pool, campaign).await;
    assert!(
        rows.iter().all(|(_, s)| s == "sent"),
        "every recipient is terminal sent exactly once: {rows:?}"
    );

    // A third tick finds nothing left to send and finalizes any residual
    // `sending` state — no re-send, no double convergence.
    let report = executor(&pool, backend, "adv-race-c")
        .tick()
        .await
        .expect("third tick");
    assert_eq!(report.recipients_sent, 0, "no residual double-send surface");
    assert_eq!(
        message_count_for(&pool, &tenant, campaign).await,
        emails.len() as i64,
        "a later tick must not re-send a converged campaign"
    );
    let (status, sent_count) = campaign_status(&pool, campaign).await;
    assert_eq!(status, "sent", "the campaign converges once, not twice");
    assert_eq!(sent_count, emails.len() as i32);
    pool.close().await;
}

// ---------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------

/// INVARIANT: a suppressed recipient is NEVER enqueued — not on the first
/// pass, not after a resend requeues failures, not under a case-variant
/// spelling of the same address. DANGER: sending to a suppressed address is
/// a compliance violation (CAN-SPAM/GDPR/CCPA) and destroys sender
/// reputation; "we retried it by accident" is not a defense.
#[tokio::test]
async fn suppressed_recipient_is_never_enqueued_even_on_resend() {
    let Some(pool) = fresh_pool("adv_suppressed_resend").await else {
        return;
    };
    let tenant = fresh_tenant("adv-supp");
    insert_tenant(&pool, &tenant).await;
    let backend = Arc::new(FakeAdmission::new());
    // Suppression list stores the canonical (lowercased) form; the contact
    // row deliberately uses a hostile case mix so only canonicalization
    // matches it.
    backend.suppress("blocked@example.test");
    let exec = executor(&pool, backend, "adv-supp-worker");

    let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    let list = insert_list(&pool, &tenant).await;
    let clean = "clean@example.test";
    let blocked = "Blocked@Example.TEST";
    for email in [clean, blocked] {
        let contact = insert_contact(&pool, &tenant, email, "active").await;
        subscribe(&pool, list, contact).await;
    }
    attach_lists(&pool, campaign, &[list], &[]).await;

    let report = exec.tick().await.expect("first tick");
    assert_eq!(report.recipients_sent, 1);
    assert_eq!(report.recipients_suppressed, 1);
    assert_eq!(
        message_count_to(&pool, &tenant, blocked).await,
        0,
        "the suppressed recipient must never produce a message row"
    );
    let rows = recipient_statuses(&pool, campaign).await;
    let blocked_row = rows
        .iter()
        .find(|(email, _)| email.eq_ignore_ascii_case(blocked))
        .expect("blocked row present");
    assert_eq!(blocked_row.1, "suppressed");

    // Resend path (the API's resend flow): campaign_jobs resend + status
    // `resending`. Only `failed` rows may requeue — the suppressed row is
    // terminal.
    sqlx::query(
        "INSERT INTO campaign_jobs (id, campaign_id, tenant_id, job_type, status) \
         VALUES ($1, $2, $3, 'resend', 'queued')",
    )
    .bind(Uuid::new_v4())
    .bind(campaign)
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("insert resend job");
    sqlx::query("UPDATE campaigns SET status = 'resending' WHERE id = $1")
        .bind(campaign)
        .execute(&pool)
        .await
        .expect("set resending");

    // Poison the clean row into `failed` so the resend has something legal
    // to requeue — proving the filter is status-based, not "requeue all".
    sqlx::query(
        "UPDATE campaign_recipients SET status = 'failed', error = 'injected' \
         WHERE campaign_id = $1 AND email = $2",
    )
    .bind(campaign)
    .bind(clean)
    .execute(&pool)
    .await
    .expect("inject failure");

    let report = exec.tick().await.expect("resend tick");
    assert_eq!(report.jobs_completed, 1);

    let rows = recipient_statuses(&pool, campaign).await;
    let blocked_row = rows
        .iter()
        .find(|(email, _)| email.eq_ignore_ascii_case(blocked))
        .expect("blocked row still present");
    assert_eq!(
        blocked_row.1, "suppressed",
        "a resend must never retry a suppressed recipient — compliance terminal"
    );
    assert_eq!(
        message_count_to(&pool, &tenant, blocked).await,
        0,
        "still zero messages to the suppressed address after resend"
    );
    // The requeued clean row reuses its idempotency key: still exactly one
    // message, never a duplicate delivery.
    assert_eq!(
        message_count_to(&pool, &tenant, clean).await,
        1,
        "resend must not duplicate an already-delivered recipient"
    );
    pool.close().await;
}

// ---------------------------------------------------------------------------
// Empty audience honesty
// ---------------------------------------------------------------------------

/// INVARIANT: an empty-audience campaign stays honest — zero recipient rows,
/// zero messages, zero sent_count — and an empty include set NEVER expands to
/// "every contact in the tenant". DANGER: fabricated sends either blast the
/// whole customer base (cardinality escape) or report success for mail that
/// never existed (silent zeros).
#[tokio::test]
async fn empty_audience_stays_honest_and_never_expands_to_every_contact() {
    let Some(pool) = fresh_pool("adv_empty_audience").await else {
        return;
    };
    let tenant = fresh_tenant("adv-empty");
    insert_tenant(&pool, &tenant).await;
    let backend = Arc::new(FakeAdmission::new());
    let exec = executor(&pool, backend, "adv-empty-worker");

    // Roster the empty campaign must NOT touch.
    let list = insert_list(&pool, &tenant).await;
    for i in 0..3 {
        let contact = insert_contact(
            &pool,
            &tenant,
            &format!("bystander-{i}@example.test"),
            "active",
        )
        .await;
        subscribe(&pool, list, contact).await;
    }

    // Campaign with NO lists and NO segment: the honest empty audience.
    let empty = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    // Second empty campaign whose list_ids points at a list with zero
    // subscribers: also empty, also must not fabricate.
    let empty_list = insert_list(&pool, &tenant).await;
    let empty_subscribed =
        insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    attach_lists(&pool, empty_subscribed, &[empty_list], &[]).await;

    let report = exec.tick().await.expect("tick");
    assert_eq!(
        report.campaigns_started, 2,
        "both empty campaigns are claimed"
    );
    assert_eq!(
        report.recipients_sent, 0,
        "an empty audience sends nothing — never the bystander roster"
    );

    for campaign in [empty, empty_subscribed] {
        let rows = recipient_emails(&pool, campaign).await;
        assert!(
            rows.is_empty(),
            "campaign {campaign} must have zero recipient rows, got {rows:?}"
        );
        assert_eq!(
            message_count_for(&pool, &tenant, campaign).await,
            0,
            "campaign {campaign} must enqueue nothing"
        );
        let (status, sent_count) = campaign_status(&pool, campaign).await;
        assert_eq!(
            sent_count, 0,
            "campaign {campaign} must not carry a fabricated sent_count"
        );
        // Production contract (campaigns.rs module docs): finalize never
        // touches campaigns without recipient rows, so the claimed empty
        // campaign stays `sending` — the API reports emptiness at send time.
        // What must NEVER happen is a fake `sent` with a non-zero count.
        assert!(
            status == "sending" || (status == "sent" && sent_count == 0),
            "empty campaign {campaign} must stay honest (got status={status}, \
             sent_count={sent_count})"
        );
    }

    // The bystander roster was never expanded into ANY campaign.
    let total_recipients: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM campaign_recipients WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("total recipients");
    assert_eq!(
        total_recipients, 0,
        "empty include must never fall through to every contact"
    );
    pool.close().await;
}

// ---------------------------------------------------------------------------
// Audience expansion: list_ids / exclude_list_ids / segment
// ---------------------------------------------------------------------------

/// INVARIANT: audience expansion is `include lists ∪ segment lists`, minus
/// `exclude lists ∪ segment excludes`, constrained by contact status
/// (default `active`/`subscribed`) and the segment's tag rules. DANGER: a
/// wrong include/exclude either mails people who opted out of that list
/// (privacy) or silently drops paying subscribers (honesty failure the other
/// way). The empty-include + tag-rule case is the ONLY cardinality escape:
/// without tag rules it must stay empty, never "everyone".
#[tokio::test]
async fn audience_expansion_honors_lists_excludes_status_and_segment_tags() {
    let Some(pool) = fresh_pool("adv_audience_rules").await else {
        return;
    };
    let tenant = fresh_tenant("adv-aud");
    insert_tenant(&pool, &tenant).await;
    let backend = Arc::new(FakeAdmission::new());
    // Admission is irrelevant here: we assert the EXPANDED audience, and a
    // zero limit keeps the drain from converting rows to messages.
    backend.set_limit(0);
    let exec = executor(&pool, backend, "adv-aud-worker");

    let l_in = insert_list(&pool, &tenant).await;
    let l_ex = insert_list(&pool, &tenant).await;
    let l_seg = insert_list(&pool, &tenant).await;
    let l_seg_ex = insert_list(&pool, &tenant).await;

    // keep: on l_in, active, no tags → IN for the list campaign.
    let keep = insert_contact(&pool, &tenant, "keep@example.test", "active").await;
    subscribe(&pool, l_in, keep).await;

    // excluded: on l_in AND l_ex → OUT (exclude wins).
    let excluded = insert_contact(&pool, &tenant, "excluded@example.test", "active").await;
    subscribe(&pool, l_in, excluded).await;
    subscribe(&pool, l_ex, excluded).await;

    // inactive: on l_in but unsubscribed contact status → OUT (default
    // statuses are active/subscribed only).
    let inactive = insert_contact(&pool, &tenant, "inactive@example.test", "unsubscribed").await;
    subscribe(&pool, l_in, inactive).await;

    // outsider: on no list → OUT.
    let _outsider = insert_contact(&pool, &tenant, "outsider@example.test", "active").await;

    // seg_member: only on the segment's list → IN via segment list union.
    let seg_member = insert_contact(&pool, &tenant, "seg-member@example.test", "active").await;
    subscribe(&pool, l_seg, seg_member).await;

    // seg_excluded: on l_in AND the segment's exclude list → OUT.
    let seg_excluded = insert_contact(&pool, &tenant, "seg-excluded@example.test", "active").await;
    subscribe(&pool, l_in, seg_excluded).await;
    subscribe(&pool, l_seg_ex, seg_excluded).await;

    // vip: on l_in with tags ["vip"] → IN under tags_all.
    let vip = insert_contact_with_tags(
        &pool,
        &tenant,
        "vip@example.test",
        "active",
        serde_json::json!(["vip"]),
    )
    .await;
    subscribe(&pool, l_in, vip).await;

    // beta-only: on no list, tags ["beta"] → IN under a tags_any segment
    // with an empty include set (the documented cardinality escape).
    let _beta = insert_contact_with_tags(
        &pool,
        &tenant,
        "beta@example.test",
        "active",
        serde_json::json!(["beta"]),
    )
    .await;

    // ---- Campaign 1: list_ids + exclude_list_ids + segment list union ----
    let seg_lists =
        insert_segment(&pool, &tenant, &[l_seg], &[l_seg_ex], serde_json::json!({})).await;
    let campaign_lists = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    attach_lists(&pool, campaign_lists, &[l_in], &[l_ex]).await;
    attach_segment(&pool, campaign_lists, seg_lists).await;

    // ---- Campaign 2: tags_all on a listed audience ----
    let seg_vip = insert_segment(
        &pool,
        &tenant,
        &[],
        &[],
        serde_json::json!({ "tags_all": ["vip"] }),
    )
    .await;
    let campaign_vip = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    attach_lists(&pool, campaign_vip, &[l_in], &[]).await;
    attach_segment(&pool, campaign_vip, seg_vip).await;

    // ---- Campaign 3: tags_any with EMPTY include (cardinality escape) ----
    let seg_beta = insert_segment(
        &pool,
        &tenant,
        &[],
        &[],
        serde_json::json!({ "tags_any": ["beta"] }),
    )
    .await;
    let campaign_beta = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    attach_segment(&pool, campaign_beta, seg_beta).await;

    let report = exec.tick().await.expect("expansion tick");
    assert_eq!(report.campaigns_started, 3);

    // Campaign 1: keep + vip (both listed+active) + seg_member (segment list
    // union). excluded/seg-excluded/inactive/outsider/beta must all be absent.
    let expanded = recipient_emails(&pool, campaign_lists).await;
    let expected = vec![
        "keep@example.test".to_string(),
        "seg-member@example.test".to_string(),
        "vip@example.test".to_string(),
    ];
    assert_eq!(
        expanded, expected,
        "list ∪ segment-list, minus excludes and inactive status — \
         excluded/seg-excluded/inactive/outsider must all be absent; \
         vip stays IN here because campaign 1 has no tag filter"
    );

    // Campaign 2: only the vip-tagged member of l_in (tags_all filter).
    let expanded = recipient_emails(&pool, campaign_vip).await;
    assert_eq!(
        expanded,
        vec!["vip@example.test".to_string()],
        "tags_all=['vip'] must filter the listed audience down to tagged contacts"
    );

    // Campaign 3: only the beta-tagged contact — NOT the whole roster.
    let expanded = recipient_emails(&pool, campaign_beta).await;
    assert_eq!(
        expanded,
        vec!["beta@example.test".to_string()],
        "tags_any with an empty include selects matching tags only — \
         never every contact in the tenant"
    );
    pool.close().await;
}

// ---------------------------------------------------------------------------
// Quota hard-stop (Free plan honesty)
// ---------------------------------------------------------------------------

/// INVARIANT: quota exhaustion is a HARD STOP that defers — it never fails
/// rows, never fabricates sends, and never burns the recipient's message.
/// When quota is restored the deferred rows deliver exactly once.
/// DANGER: "helpful" retries at the cap create unbillable double-sends;
/// marking deferred rows `failed` tells the customer their campaign died
/// when it is merely waiting; reporting `sent` without enqueueing is a lie.
#[tokio::test]
async fn quota_hard_stop_defers_without_fabricating_sends_then_recovers_once() {
    let Some(pool) = fresh_pool("adv_quota_hard_stop").await else {
        return;
    };
    let tenant = fresh_tenant("adv-quota");
    insert_tenant(&pool, &tenant).await;
    let backend = Arc::new(FakeAdmission::new());
    backend.set_limit(0);
    let exec = executor(&pool, backend.clone(), "adv-quota-worker");

    let campaign = insert_ready_campaign(&pool, &tenant, "scheduled", Some(Utc::now())).await;
    let list = insert_list(&pool, &tenant).await;
    let mut emails = Vec::new();
    for i in 0..3 {
        let email = format!("quota-{i}@example.test");
        let contact = insert_contact(&pool, &tenant, &email, "active").await;
        subscribe(&pool, list, contact).await;
        emails.push(email);
    }
    attach_lists(&pool, campaign, &[list], &[]).await;

    // Tick 1: Free hard-stop. Everything defers; nothing is sent or failed.
    let report = exec.tick().await.expect("hard-stop tick");
    assert_eq!(report.recipients_sent, 0, "hard-stop sends nothing");
    assert_eq!(
        report.recipients_deferred, 3,
        "every recipient defers at the cap — none fail"
    );
    assert_eq!(
        report.recipients_failed, 0,
        "a quota deferral is not a failure"
    );
    assert_eq!(
        message_count_for(&pool, &tenant, campaign).await,
        0,
        "the hard-stop must not fabricate enqueues"
    );
    let (status, sent_count) = campaign_status(&pool, campaign).await;
    assert_eq!(status, "sending", "deferred work keeps the campaign live");
    assert_eq!(sent_count, 0, "no phantom sent_count at the cap");
    let rows = recipient_statuses(&pool, campaign).await;
    assert!(
        rows.iter().all(|(_, s)| s == "queued"),
        "deferred rows stay queued for recovery: {rows:?}"
    );

    // Quota restored (e.g. plan upgrade). Next tick delivers each row ONCE.
    backend.set_limit(10);
    let report = exec.tick().await.expect("recovery tick");
    assert_eq!(report.recipients_sent, 3);
    for email in &emails {
        assert_eq!(
            message_count_to(&pool, &tenant, email).await,
            1,
            "recovery must deliver {email} exactly once (no double-billing \
             from the deferred attempt)"
        );
    }
    let (status, sent_count) = campaign_status(&pool, campaign).await;
    assert_eq!(status, "sent");
    assert_eq!(sent_count, 3);

    // And the idempotency key blocks any later re-enqueue of the same
    // (campaign, contact) pair even if a stale row is re-claimed.
    sqlx::query(
        "UPDATE campaign_recipients SET status = 'queued', message_id = NULL \
         WHERE campaign_id = $1",
    )
    .bind(campaign)
    .execute(&pool)
    .await
    .expect("stale requeue");
    sqlx::query("UPDATE campaigns SET status = 'sending' WHERE id = $1")
        .bind(campaign)
        .execute(&pool)
        .await
        .expect("reopen");
    let _ = exec.tick().await.expect("stale tick");
    for email in &emails {
        assert_eq!(
            message_count_to(&pool, &tenant, email).await,
            1,
            "the per-(campaign, contact) idempotency key must make a stale \
             re-claim a no-op for {email}"
        );
    }
    pool.close().await;
}
