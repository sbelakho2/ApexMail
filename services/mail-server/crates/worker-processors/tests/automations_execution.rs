//! DB-backed tests for the automation executor (migration 224 +
//! `worker_processors::automations`).
//!
//! These tests live in `worker-processors` — which has NO dependency on the
//! sales-autopilot crate — so a green run here proves customer automation
//! execution works standalone, without the owner's sales-brain process.
//!
//! Every test provisions its own canonical database through the production
//! migrator ([`migrator::test_support::fresh_canonical_pool`]): a soft skip is
//! allowed ONLY when `TEST_DATABASE_URL` is unset; a configured environment
//! that cannot provision the database panics.
//!
//! Admission is exercised through the SHARED `SendAdmissionService` with the
//! same deterministic in-memory backend shape the dispatcher tests use: one
//! counter per tenant, usage-event-id de-duplication, suppression list. The
//! executor itself only ever sees the public service, exactly like production
//! (which constructs it over `PostgresAdmissionBackend`).

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use billing_service::send_admission::{SendAdmissionBackend, SendAdmissionService};
use billing_service::usage::{QuotaRecordResult, UsageError};
use worker_processors::automations::{
    AutomationExecutor, AUTOMATION_MARKETING_CATEGORY, AUTOMATION_REPLY_CATEGORY,
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

async fn fresh_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        // F01: TEST_DATABASE_URL is configured, so a provisioning failure is
        // an infrastructure failure — fail the test, never soft-skip.
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// The shared admission contract with the knobs these tests need (same shape
/// as `tests/dispatcher_integration.rs`): unlimited by default, event-id
/// de-duplication, event-id keyed rollback, suppression list.
#[derive(Debug)]
struct FakeAdmissionBackend {
    limit: AtomicI64,
    used: AtomicI64,
    reserves: AtomicUsize,
    rollbacks: AtomicUsize,
    events: Mutex<std::collections::HashMap<Uuid, i64>>,
    suppressed: Mutex<Vec<String>>,
}

impl FakeAdmissionBackend {
    fn new() -> Self {
        Self {
            limit: AtomicI64::new(-1),
            used: AtomicI64::new(0),
            reserves: AtomicUsize::new(0),
            rollbacks: AtomicUsize::new(0),
            events: Mutex::new(std::collections::HashMap::new()),
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

    fn reserves(&self) -> usize {
        self.reserves.load(Ordering::SeqCst)
    }

    fn used(&self) -> i64 {
        self.used.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl SendAdmissionBackend for FakeAdmissionBackend {
    async fn record_send_usage(
        &self,
        _tenant_id: &str,
        quantity: i64,
        event_id: Uuid,
    ) -> Result<QuotaRecordResult, UsageError> {
        self.reserves.fetch_add(1, Ordering::SeqCst);
        let mut events = self.events.lock().unwrap();
        if let Some(previous) = events.get(&event_id) {
            assert_eq!(*previous, quantity, "duplicate must carry same quantity");
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
        events.insert(event_id, quantity);
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
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        let mut events = self.events.lock().unwrap();
        if events.remove(&event_id).is_some() {
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

fn executor(pool: &PgPool, backend: Arc<FakeAdmissionBackend>) -> AutomationExecutor {
    AutomationExecutor::new(
        pool.clone(),
        SendAdmissionService::new(backend),
        "automation-test-worker",
    )
}

fn fresh_tenant() -> String {
    apexmail_lib::id::generate_id("ten", 22)
}

async fn insert_tenant(pool: &PgPool, tenant: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $2, $3, 'free', 'active')",
    )
    .bind(tenant)
    .bind(format!("Automation Test {tenant}"))
    .bind(format!("auto-{tenant}"))
    .execute(pool)
    .await
    .expect("insert tenant");
}

/// Verified + DKIM-ready sender domain (the gate the send path resolves).
async fn insert_domain(pool: &PgPool, tenant: &str) -> String {
    let domain = format!(
        "auto-{}.example.com",
        &Uuid::new_v4().simple().to_string()[..12]
    );
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified,
         dkim_selector, dkim_public_key, dkim_private_key)
         VALUES ($1, $2, $3, 'verified', true, true, true, 'test-selector', 'test-public-key', 'dkim:v1:test')",
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
        "INSERT INTO templates (id, tenant_id, name, slug, subject, html_body, text_body)
         VALUES ($1, $2, $3, $4, 'Hello {{first_name}}', '<p>Hi {{name}} ({{email}})</p>', 'Hi {{first_name}}')",
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

#[allow(clippy::too_many_arguments)]
async fn insert_automation(
    pool: &PgPool,
    tenant: &str,
    name: &str,
    trigger: serde_json::Value,
    conditions: serde_json::Value,
    actions: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO automations (id, tenant_id, name, trigger_config, actions, conditions, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'enabled')",
    )
    .bind(id)
    .bind(tenant)
    .bind(name)
    .bind(&trigger)
    .bind(&actions)
    .bind(&conditions)
    .execute(pool)
    .await
    .expect("insert automation");
    id
}

fn send_email_action(from: &str, template_id: &str) -> serde_json::Value {
    json!([{
        "type": "send_email",
        "config": { "template_id": template_id, "from": from, "delay_minutes": 0 }
    }])
}

/// Insert a subscribed contact; the migration-224 trigger emits contact.created.
async fn insert_contact(pool: &PgPool, tenant: &str, email: &str, tags: &[&str]) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO contacts (tenant_id, email, name, tags, status)
         VALUES ($1, $2, $3, $4, 'subscribed') RETURNING id",
    )
    .bind(tenant)
    .bind(email)
    .bind("Ada Lovelace")
    .bind(json!(tags))
    .fetch_one(pool)
    .await
    .expect("insert contact")
}

async fn message_categories(pool: &PgPool, tenant: &str) -> Vec<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT id::text, message_category FROM messages WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await
    .expect("messages")
}

async fn queue_categories(pool: &PgPool, tenant: &str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT message_category FROM email_queue WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await
    .expect("email_queue")
}

async fn run_rows(
    pool: &PgPool,
    tenant: &str,
    automation_id: Uuid,
) -> Vec<(String, Option<String>, bool, String)> {
    sqlx::query_as::<_, (String, Option<String>, bool, String)>(
        "SELECT status, skip_reason, retryable, trigger_kind FROM automation_runs
         WHERE tenant_id = $1 AND automation_id = $2 ORDER BY started_at",
    )
    .bind(tenant)
    .bind(automation_id)
    .fetch_all(pool)
    .await
    .expect("automation_runs")
}

async fn action_rows(
    pool: &PgPool,
    tenant: &str,
) -> Vec<(
    String,
    String,
    Option<String>,
    Option<Uuid>,
    serde_json::Value,
)> {
    sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            Option<Uuid>,
            serde_json::Value,
        ),
    >(
        "SELECT action_type, status, reason, message_id, detail FROM automation_run_actions
         WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await
    .expect("automation_run_actions")
}

async fn event_status(pool: &PgPool, tenant: &str, event_key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT status FROM automation_trigger_events WHERE tenant_id = $1 AND event_key = $2",
    )
    .bind(tenant)
    .bind(event_key)
    .fetch_optional(pool)
    .await
    .expect("event status")
}

// ---------------------------------------------------------------------------
// Crash-injection machinery (trigger-based per-statement fault injection)
// ---------------------------------------------------------------------------

/// Statement-level fault injection, modeled on the api-server route tests'
/// `_fault_injection_*` machinery: a BEFORE trigger raises on the (skip+1)-th
/// write to `table`. Everything committed before the raise STAYS committed
/// (the executor runs on autocommit statements and explicit transactions that
/// commit before the armed statement), so arming a fault at statement N
/// models a process death at exactly that point of the executor's sequence.
/// Every test provisions its own canonical database, so armed triggers and
/// state tables never leak between tests and `disarm` only has to undo its
/// own tag.
mod fi {
    use sqlx::PgPool;

    const STATE_TABLE: &str = "_fault_injection_state";
    const FUNCTION: &str = "_fault_injection_trigger_fn";

    async fn ensure_machinery(pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {STATE_TABLE} (\
                 tag TEXT PRIMARY KEY, \
                 fires INT NOT NULL DEFAULT 0, \
                 skip INT NOT NULL, \
                 done BOOLEAN NOT NULL DEFAULT FALSE)"
        ))
        .execute(pool)
        .await?;
        sqlx::query(&format!(
            "CREATE OR REPLACE FUNCTION {FUNCTION}() RETURNS trigger AS $body$ \
             DECLARE \
               st {STATE_TABLE}%ROWTYPE; \
             BEGIN \
               SELECT * INTO st FROM {STATE_TABLE} WHERE tag = TG_ARGV[0]; \
               IF NOT FOUND THEN \
                 RETURN NULL; \
               END IF; \
               UPDATE {STATE_TABLE} SET fires = fires + 1 WHERE tag = TG_ARGV[0]; \
               IF st.fires >= st.skip THEN \
                 RAISE EXCEPTION 'fault-injected database failure (tag=%, table=%)', \
                   TG_ARGV[0], TG_TABLE_NAME; \
               END IF; \
               RETURN NULL; \
             END; \
             $body$ LANGUAGE plpgsql"
        ))
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Arm: the first `skip` INSERT statements against `table` succeed, every
    /// INSERT from the (`skip` + 1)-th on fails with a database error.
    /// Statement-level counting: one multi-row statement is ONE fire.
    ///
    /// The trigger is INSERT-only ON PURPOSE: a statement-level trigger
    /// declared `INSERT OR UPDATE` fires on BOTH command events of an upsert
    /// (`INSERT ... ON CONFLICT DO UPDATE`), so every executor upsert would
    /// consume TWO fires and the skip window would be untargetable. The
    /// executor's writes under test (run rows, action records) are all
    /// INSERTs.
    pub async fn arm_write_fault(pool: &PgPool, table: &str, tag: &str, skip: usize) {
        ensure_machinery(pool).await.expect("fault machinery");
        let trigger = format!("_fi_{tag}");
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger} ON {table}"))
            .execute(pool)
            .await
            .expect("drop stale trigger");
        sqlx::query(&format!(
            "CREATE TRIGGER {trigger} BEFORE INSERT ON {table} \
             FOR EACH STATEMENT EXECUTE FUNCTION {FUNCTION}('{tag}')"
        ))
        .execute(pool)
        .await
        .expect("arm trigger");
        sqlx::query(&format!(
            "INSERT INTO {STATE_TABLE} (tag, skip) VALUES ($1, $2) \
             ON CONFLICT (tag) DO UPDATE SET skip = EXCLUDED.skip, fires = 0, done = FALSE"
        ))
        .bind(tag)
        .bind(skip as i32)
        .execute(pool)
        .await
        .expect("arm state");
    }

    /// Remove the armed fault: recovery (the re-run) may proceed.
    pub async fn disarm(pool: &PgPool, tag: &str) {
        let trigger = format!("_fi_{tag}");
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger} ON automation_runs"))
            .execute(pool)
            .await
            .expect("disarm trigger (automation_runs)");
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger} ON automation_run_actions"))
            .execute(pool)
            .await
            .expect("disarm trigger (automation_run_actions)");
        sqlx::query(&format!("DELETE FROM {STATE_TABLE} WHERE tag = $1"))
            .bind(tag)
            .execute(pool)
            .await
            .expect("disarm state");
    }
}

/// Simulate the crash residue on an event whose lease was abandoned: the
/// claim left `status = 'processing'` with a `locked_until` deadline that no
/// live process will renew. Expiring it is what the reclaim branch of
/// `claim_due_events` keys on (`locked_until < NOW()`).
async fn abandon_event_lease(pool: &PgPool, tenant: &str, event_key: &str) {
    sqlx::query(
        "UPDATE automation_trigger_events \
         SET locked_until = NOW() - interval '1 second' \
         WHERE tenant_id = $1 AND event_key = $2",
    )
    .bind(tenant)
    .bind(event_key)
    .execute(pool)
    .await
    .expect("expire lease");
}

async fn contact_tags(pool: &PgPool, tenant: &str, contact: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT tags FROM contacts WHERE tenant_id = $1 AND id = $2")
        .bind(tenant)
        .bind(contact)
        .fetch_one(pool)
        .await
        .expect("contact tags")
}

// ---------------------------------------------------------------------------
// 1. Matching trigger -> one run + one admission-gated queued message
// ---------------------------------------------------------------------------

#[tokio::test]
async fn matching_trigger_enqueues_one_admission_gated_message() {
    let Some(pool) = fresh_pool("autoexec_match").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;
    let automation = insert_automation(
        &pool,
        &tenant,
        "Welcome",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        send_email_action(&format!("welcome@{domain}"), &template),
    )
    .await;

    let contact = insert_contact(&pool, &tenant, "ada@example.com", &["vip"]).await;
    let event_key = format!("contact.created:{contact}");
    assert_eq!(
        event_status(&pool, &tenant, &event_key).await.as_deref(),
        Some("pending"),
        "the contacts trigger must emit a contact.created event"
    );

    let report = engine.tick().await.expect("tick");
    assert_eq!(report.events_claimed, 1);
    assert_eq!(report.runs_succeeded, 1, "one run succeeded: {report:?}");
    assert_eq!(report.actions_enqueued, 1);

    // The message is admission-gated: explicit marketing category on BOTH the
    // message row and the queue row (never the schema default by accident).
    let messages = message_categories(&pool, &tenant).await;
    assert_eq!(messages.len(), 1, "one message queued");
    assert_eq!(messages[0].1, AUTOMATION_MARKETING_CATEGORY);
    assert_eq!(messages[0].1, "marketing");
    assert_eq!(
        queue_categories(&pool, &tenant).await,
        vec!["marketing".to_string()]
    );

    // Admission was the gate, and the quota was reserved exactly once.
    assert_eq!(backend.reserves(), 1);
    assert_eq!(backend.used(), 1);

    // Observability: the run and the per-action record answer what happened.
    let runs = run_rows(&pool, &tenant, automation).await;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].0, "succeeded");
    let actions = action_rows(&pool, &tenant).await;
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].0, "send_email");
    assert_eq!(actions[0].1, "succeeded");
    assert_eq!(actions[0].3, Some(Uuid::parse_str(&messages[0].0).unwrap()));
    assert_eq!(
        event_status(&pool, &tenant, &event_key).await.as_deref(),
        Some("processed")
    );
}

// ---------------------------------------------------------------------------
// 2. Replaying the same event (even with lost bookkeeping) never sends twice
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replaying_the_same_event_never_sends_twice() {
    let Some(pool) = fresh_pool("autoexec_replay").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;
    let automation = insert_automation(
        &pool,
        &tenant,
        "Replay",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        send_email_action(&format!("welcome@{domain}"), &template),
    )
    .await;
    let contact = insert_contact(&pool, &tenant, "replay@example.com", &[]).await;
    let event_key = format!("contact.created:{contact}");

    engine.tick().await.expect("first tick");
    assert_eq!(message_categories(&pool, &tenant).await.len(), 1);

    // (a) Plain replay: the same event is claimed again (producer retry /
    //     lease expiry). The run is terminal, so nothing re-executes.
    sqlx::query(
        "UPDATE automation_trigger_events SET status = 'pending', available_at = NOW(), \
         attempts = 0, locked_until = NULL WHERE tenant_id = $1 AND event_key = $2",
    )
    .bind(&tenant)
    .bind(&event_key)
    .execute(&pool)
    .await
    .expect("reset event");
    assert!(
        !engine
            .ingest_event(
                &tenant,
                "contact.created",
                &event_key,
                Some(contact),
                None,
                json!({})
            )
            .await
            .expect("ingest replay"),
        "ingesting the same event key is a no-op"
    );

    let second = engine.tick().await.expect("second tick");
    assert_eq!(second.runs_replayed, 1, "terminal run replayed: {second:?}");
    assert_eq!(message_categories(&pool, &tenant).await.len(), 1);

    // (b) Worst-case partial commit: the message committed but the action
    //     bookkeeping was lost (crash before record_action) and the run row
    //     is still 'running'. The retry must hit the derived message
    //     idempotency key and reuse the existing message.
    sqlx::query(
        "UPDATE automation_runs SET status = 'running', finished_at = NULL, updated_at = NOW() \
         WHERE tenant_id = $1 AND automation_id = $2",
    )
    .bind(&tenant)
    .bind(automation)
    .execute(&pool)
    .await
    .expect("reset run");
    sqlx::query("DELETE FROM automation_run_actions WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("delete action bookkeeping");
    sqlx::query(
        "UPDATE automation_trigger_events SET status = 'pending', available_at = NOW(), \
         attempts = 0, locked_until = NULL WHERE tenant_id = $1 AND event_key = $2",
    )
    .bind(&tenant)
    .bind(&event_key)
    .execute(&pool)
    .await
    .expect("reset event again");

    engine.tick().await.expect("third tick");

    let messages = message_categories(&pool, &tenant).await;
    assert_eq!(messages.len(), 1, "no second message after the retry");
    assert_eq!(
        queue_categories(&pool, &tenant).await.len(),
        1,
        "no second queue row after the retry"
    );
    let actions = action_rows(&pool, &tenant).await;
    assert_eq!(actions.len(), 1, "the action record was restored");
    assert_eq!(actions[0].1, "succeeded");
    assert_eq!(
        actions[0].4["duplicate"], true,
        "the retry re-enqueued through the idempotency key: {:?}",
        actions[0].4
    );
    assert_eq!(backend.used(), 1, "quota reserved exactly once");
}

// ---------------------------------------------------------------------------
// 3. A non-matching condition -> skipped run with the reason, no message
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_matching_condition_records_skipped_run_without_sending() {
    let Some(pool) = fresh_pool("autoexec_condition").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;
    let automation = insert_automation(
        &pool,
        &tenant,
        "Vip only",
        json!({"type": "event", "event": "contact.created"}),
        json!({"all": [{"field": "tags", "operator": "contains", "value": "vip"}]}),
        send_email_action(&format!("welcome@{domain}"), &template),
    )
    .await;

    insert_contact(&pool, &tenant, "nobody@example.com", &["standard"]).await;

    let report = engine.tick().await.expect("tick");
    assert_eq!(report.runs_skipped, 1, "{report:?}");
    assert_eq!(report.actions_enqueued, 0);

    let runs = run_rows(&pool, &tenant, automation).await;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].0, "skipped");
    assert!(
        runs[0]
            .1
            .as_deref()
            .unwrap_or_default()
            .starts_with("condition_not_met"),
        "the skip reason must be recorded: {:?}",
        runs[0].1
    );
    assert!(message_categories(&pool, &tenant).await.is_empty());
    assert!(action_rows(&pool, &tenant).await.is_empty());
    assert_eq!(
        backend.reserves(),
        0,
        "no admission call for a skipped rule"
    );
}

// ---------------------------------------------------------------------------
// 4. A suppressed recipient is a terminal skip, not a retry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn suppressed_recipient_is_a_terminal_skip_not_a_retry() {
    let Some(pool) = fresh_pool("autoexec_suppressed").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    backend.suppress("blocked@example.com");
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;
    let automation = insert_automation(
        &pool,
        &tenant,
        "Suppressed",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        send_email_action(&format!("welcome@{domain}"), &template),
    )
    .await;
    let contact = insert_contact(&pool, &tenant, "blocked@example.com", &[]).await;
    let event_key = format!("contact.created:{contact}");

    let report = engine.tick().await.expect("tick");
    assert_eq!(report.runs_skipped, 1);
    assert_eq!(report.events_deferred, 0, "a suppression is not retried");
    assert_eq!(report.actions_enqueued, 0);
    assert!(message_categories(&pool, &tenant).await.is_empty());

    let actions = action_rows(&pool, &tenant).await;
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].1, "skipped");
    assert_eq!(actions[0].2.as_deref(), Some("suppressed_recipient"));

    let runs = run_rows(&pool, &tenant, automation).await;
    assert_eq!(runs[0].0, "skipped");
    assert!(!runs[0].2, "terminal skip must not be retryable");
    assert_eq!(
        event_status(&pool, &tenant, &event_key).await.as_deref(),
        Some("processed"),
        "the event is settled, not left due for a retry loop"
    );

    // A second tick changes nothing: the run is terminal and the event is
    // processed, so the suppression is never retried.
    let again = engine.tick().await.expect("second tick");
    assert_eq!(again.events_claimed, 0);
    assert!(message_categories(&pool, &tenant).await.is_empty());
    assert_eq!(backend.used(), 0, "no quota reserved for a suppressed send");
}

// ---------------------------------------------------------------------------
// 5. Quota refusal is a RETRYABLE deferral that resumes exactly once
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quota_refusal_defers_and_resumes_without_double_sending() {
    let Some(pool) = fresh_pool("autoexec_quota").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    backend.set_limit(0); // deny every reservation
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;
    let automation = insert_automation(
        &pool,
        &tenant,
        "Quota",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        send_email_action(&format!("welcome@{domain}"), &template),
    )
    .await;
    let contact = insert_contact(&pool, &tenant, "quota@example.com", &[]).await;
    let event_key = format!("contact.created:{contact}");

    let first = engine.tick().await.expect("first tick");
    assert_eq!(
        first.events_deferred, 1,
        "quota exhaustion defers: {first:?}"
    );
    assert_eq!(first.runs_failed, 1);
    assert!(message_categories(&pool, &tenant).await.is_empty());

    let runs = run_rows(&pool, &tenant, automation).await;
    assert_eq!(runs[0].0, "failed");
    assert!(runs[0].2, "a quota refusal is retryable");
    assert_eq!(
        event_status(&pool, &tenant, &event_key).await.as_deref(),
        Some("pending"),
        "the event is rescheduled, not dropped"
    );

    // Quota is restored; the retry resumes the SAME run and sends once.
    backend.set_limit(-1);
    sqlx::query(
        "UPDATE automation_trigger_events SET available_at = NOW() \
         WHERE tenant_id = $1 AND event_key = $2",
    )
    .bind(&tenant)
    .bind(&event_key)
    .execute(&pool)
    .await
    .expect("make event due");

    let second = engine.tick().await.expect("second tick");
    assert_eq!(second.runs_started, 1, "the failed run resumes: {second:?}");
    assert_eq!(second.runs_succeeded, 1);

    let messages = message_categories(&pool, &tenant).await;
    assert_eq!(messages.len(), 1, "exactly one message after the retry");
    assert_eq!(messages[0].1, AUTOMATION_MARKETING_CATEGORY);
    assert_eq!(queue_categories(&pool, &tenant).await.len(), 1);
    assert_eq!(
        event_status(&pool, &tenant, &event_key).await.as_deref(),
        Some("processed")
    );
    let actions = action_rows(&pool, &tenant).await;
    assert_eq!(actions.len(), 1, "one action row, updated by the resume");
    assert_eq!(actions[0].1, "succeeded");
}

// ---------------------------------------------------------------------------
// 6. Unsupported trigger / action kinds are reported, never silently dropped
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unsupported_trigger_and_action_kinds_are_reported() {
    let Some(pool) = fresh_pool("autoexec_unsupported").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;

    // Stored kind with no meaning anywhere: must be reported, not ignored.
    let schedule_rule = insert_automation(
        &pool,
        &tenant,
        "Scheduled",
        json!({"type": "schedule", "cron": "0 9 * * *"}),
        json!({}),
        send_email_action(&format!("welcome@{domain}"), &template),
    )
    .await;
    // Stored action kind the executor does not implement.
    let delay_rule = insert_automation(
        &pool,
        &tenant,
        "Delayed",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        json!([{"type": "delay", "config": {"minutes": 5}}]),
    )
    .await;

    insert_contact(&pool, &tenant, "unsupported@example.com", &[]).await;

    let report = engine.tick().await.expect("tick");
    assert_eq!(report.actions_enqueued, 0);

    let schedule_runs = run_rows(&pool, &tenant, schedule_rule).await;
    assert_eq!(schedule_runs.len(), 1, "unsupported trigger reported once");
    assert_eq!(schedule_runs[0].0, "skipped");
    assert_eq!(schedule_runs[0].3, "schedule");
    assert!(
        schedule_runs[0]
            .1
            .as_deref()
            .unwrap_or_default()
            .contains("unsupported trigger kind"),
        "reason must name the unsupported kind: {:?}",
        schedule_runs[0].1
    );

    let delay_runs = run_rows(&pool, &tenant, delay_rule).await;
    assert_eq!(delay_runs.len(), 1);
    assert_eq!(delay_runs[0].0, "skipped");

    // The delay action row is the report.
    let actions: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT a.action_type, a.status, a.reason, r.trigger_kind \
         FROM automation_run_actions a JOIN automation_runs r ON r.id = a.run_id \
         WHERE a.tenant_id = $1 AND r.automation_id = $2",
    )
    .bind(&tenant)
    .bind(delay_rule)
    .fetch_all(&pool)
    .await
    .expect("actions");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].0, "delay");
    assert_eq!(actions[0].1, "unsupported");
    assert!(
        actions[0]
            .2
            .as_deref()
            .unwrap_or_default()
            .contains("unsupported action kind 'delay'"),
        "reason must name the unsupported action: {:?}",
        actions[0].2
    );

    // Re-running the tick does not duplicate the unsupported-trigger report.
    sqlx::query("UPDATE automation_trigger_events SET status = 'pending', available_at = NOW(), attempts = 0, locked_until = NULL WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("reset events");
    engine.tick().await.expect("second tick");
    assert_eq!(
        run_rows(&pool, &tenant, schedule_rule).await.len(),
        1,
        "the unsupported-trigger diagnosis is recorded exactly once"
    );
    assert!(message_categories(&pool, &tenant).await.is_empty());
}

// ---------------------------------------------------------------------------
// 7. Tenant isolation: tenant A's rule never sees tenant B's events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tenant_a_rule_never_touches_tenant_b() {
    let Some(pool) = fresh_pool("autoexec_isolation").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    let engine = executor(&pool, backend.clone());

    let tenant_a = fresh_tenant();
    let tenant_b = fresh_tenant();
    insert_tenant(&pool, &tenant_a).await;
    insert_tenant(&pool, &tenant_b).await;
    let domain_a = insert_domain(&pool, &tenant_a).await;
    let domain_b = insert_domain(&pool, &tenant_b).await;
    let template_a = insert_template(&pool, &tenant_a).await;
    let template_b = insert_template(&pool, &tenant_b).await;

    let rule_a = insert_automation(
        &pool,
        &tenant_a,
        "A rule",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        send_email_action(&format!("a@{domain_a}"), &template_a),
    )
    .await;
    let rule_b = insert_automation(
        &pool,
        &tenant_b,
        "B rule",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        send_email_action(&format!("b@{domain_b}"), &template_b),
    )
    .await;

    // Only tenant B has an event/contact.
    insert_contact(&pool, &tenant_b, "b-contact@example.com", &[]).await;

    let report = engine.tick().await.expect("tick");
    assert_eq!(report.runs_succeeded, 1);

    assert!(
        run_rows(&pool, &tenant_a, rule_a).await.is_empty(),
        "tenant A's rule must not run on tenant B's event"
    );
    let runs_b = run_rows(&pool, &tenant_b, rule_b).await;
    assert_eq!(runs_b.len(), 1);
    assert_eq!(runs_b[0].0, "succeeded");

    assert!(
        message_categories(&pool, &tenant_a).await.is_empty(),
        "no message may be enqueued for tenant A"
    );
    let messages_b = message_categories(&pool, &tenant_b).await;
    assert_eq!(messages_b.len(), 1);
    assert_eq!(messages_b[0].1, "marketing");
    assert_eq!(queue_categories(&pool, &tenant_a).await.len(), 0);
    assert_eq!(queue_categories(&pool, &tenant_b).await.len(), 1);
}

// ---------------------------------------------------------------------------
// 8. A 1:1 reply to an inbound message is admitted as transactional
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inbound_reply_trigger_sends_transactional() {
    let Some(pool) = fresh_pool("autoexec_reply").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;
    let automation = insert_automation(
        &pool,
        &tenant,
        "Auto reply",
        json!({"type": "event", "event": "message.received"}),
        json!({}),
        send_email_action(&format!("support@{domain}"), &template),
    )
    .await;

    // The schema trigger on inbound_messages emits message.received.
    sqlx::query(
        "INSERT INTO inbound_messages (id, tenant_id, from_email, to_email, subject, body_text)
         VALUES ($1, $2, 'customer@example.net', 'support@example.com', 'Question', 'Help please')",
    )
    .bind(apexmail_lib::id::generate_id("inb", 22))
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("insert inbound message");

    let report = engine.tick().await.expect("tick");
    assert_eq!(report.runs_succeeded, 1, "{report:?}");

    let messages = message_categories(&pool, &tenant).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].1, AUTOMATION_REPLY_CATEGORY,
        "a 1:1 reply to a message the recipient sent is transactional"
    );
    assert_eq!(messages[0].1, "transactional");

    let recipient: String =
        sqlx::query_scalar("SELECT to_emails->>0 FROM messages WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("recipient");
    assert_eq!(recipient, "customer@example.net");

    let runs = run_rows(&pool, &tenant, automation).await;
    assert_eq!(runs[0].0, "succeeded");
    assert_eq!(backend.used(), 1);
}

// ---------------------------------------------------------------------------
// 9. Crash consistency: a death at ANY point of the executor's sequence is
//    recovered by the lease + the derived identities, without operator help
// ---------------------------------------------------------------------------

/// Window 1 — crash between CLAIM and any effect. The fault kills the tick at
/// the statement that would open the run (before admission, before any send).
/// The abandoned lease must be reclaimed, the event executed exactly once,
/// and the settled event never re-claimed.
#[tokio::test]
async fn crash_between_claim_and_any_effect_is_recovered_by_the_lease() {
    let Some(pool) = fresh_pool("autoexec_crash_claim").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;
    let automation = insert_automation(
        &pool,
        &tenant,
        "Crash at run open",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        send_email_action(&format!("welcome@{domain}"), &template),
    )
    .await;
    let contact = insert_contact(&pool, &tenant, "crash-claim@example.com", &[]).await;
    let event_key = format!("contact.created:{contact}");

    // The process dies at the exact statement that would create the run.
    fi::arm_write_fault(&pool, "automation_runs", "crash_claim", 0).await;
    let crashed = engine.tick().await;
    assert!(
        crashed.is_err(),
        "the injected fault must kill the tick mid-execution"
    );

    // Crash state: the event was claimed (lease held by a dead process) but
    // nothing durable happened — no run, no admission, no send.
    let (status, locked_until): (String, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "SELECT status, locked_until FROM automation_trigger_events \
         WHERE tenant_id = $1 AND event_key = $2",
    )
    .bind(&tenant)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .expect("event row");
    assert_eq!(status, "processing", "the claim is stranded by the crash");
    assert!(locked_until.is_some(), "the dead worker held a lease");
    assert_eq!(run_rows(&pool, &tenant, automation).await.len(), 0);
    assert!(message_categories(&pool, &tenant).await.is_empty());
    assert_eq!(
        backend.reserves(),
        0,
        "the crash happened before the admission gate"
    );

    // Recovery needs NO operator: disarm the fault and let the lease expire —
    // the reclaim branch of the claim picks the event back up.
    fi::disarm(&pool, "crash_claim").await;
    abandon_event_lease(&pool, &tenant, &event_key).await;
    let recovered = engine.tick().await.expect("recovery tick");
    assert_eq!(
        recovered.events_claimed, 1,
        "the abandoned lease must be reclaimed"
    );
    assert_eq!(recovered.runs_succeeded, 1, "{recovered:?}");
    assert_eq!(recovered.actions_enqueued, 1);

    // Exactly once: one run, one message, one queue row, one action record,
    // one quota reservation.
    assert_eq!(run_rows(&pool, &tenant, automation).await.len(), 1);
    assert_eq!(message_categories(&pool, &tenant).await.len(), 1);
    assert_eq!(queue_categories(&pool, &tenant).await.len(), 1);
    assert_eq!(action_rows(&pool, &tenant).await.len(), 1);
    assert_eq!(backend.used(), 1);
    assert_eq!(backend.reserves(), 1);
    assert_eq!(
        event_status(&pool, &tenant, &event_key).await.as_deref(),
        Some("processed")
    );

    // The settled event is never re-claimed: the system converged.
    let drained = engine.tick().await.expect("drain tick");
    assert_eq!(drained.events_claimed, 0);
}

/// Window 2 — a HALF-EXECUTED action ladder (crash after 2 of 3 actions
/// physically executed, only the first recorded). Recovery must resume the
/// SAME run and re-execute the unrecorded prefix WITHOUT repeating its
/// effects: the tag stays a set of one, the list keeps one membership row,
/// and the send happens exactly once.
#[tokio::test]
async fn half_executed_action_ladder_resumes_without_repeating_effects() {
    let Some(pool) = fresh_pool("autoexec_crash_ladder").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;
    let list_id = Uuid::new_v4();
    sqlx::query("INSERT INTO lists (id, tenant_id, name) VALUES ($1, $2, 'Crash Ladder')")
        .bind(list_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("insert list");

    let ladder = json!([
        { "type": "add_tag", "config": { "tag": "vip" } },
        { "type": "add_to_list", "config": { "list_id": list_id.to_string() } },
        { "type": "send_email",
          "config": { "template_id": template, "from": format!("welcome@{domain}") } },
    ]);
    let automation = insert_automation(
        &pool,
        &tenant,
        "Ladder",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        ladder,
    )
    .await;
    let contact = insert_contact(&pool, &tenant, "ladder@example.com", &[]).await;
    let event_key = format!("contact.created:{contact}");

    // Record-action #1 lands (action 0 executed AND recorded), record-action
    // #2 raises: actions 0 AND 1 physically executed, only 0 is recorded, and
    // the process dies before the send.
    fi::arm_write_fault(&pool, "automation_run_actions", "crash_ladder", 1).await;
    assert!(
        engine.tick().await.is_err(),
        "the fault must kill the tick mid-ladder"
    );

    // The half-executed crash state, verified row by row.
    let tags = contact_tags(&pool, &tenant, contact).await;
    assert_eq!(
        tags,
        json!(["vip"]),
        "action 0 executed exactly once despite losing its bookkeeping"
    );
    let list_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM list_subscribers \
         WHERE list_id = $1 AND contact_id = $2",
    )
    .bind(list_id)
    .bind(contact)
    .fetch_one(&pool)
    .await
    .expect("list membership");
    assert_eq!(list_rows, 1, "action 1 executed exactly once");
    let recorded: Vec<(i32, String)> = sqlx::query_as(
        "SELECT action_index, status FROM automation_run_actions WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_all(&pool)
    .await
    .expect("recorded actions");
    assert_eq!(
        recorded,
        vec![(0, "succeeded".to_string())],
        "only the first action's bookkeeping survived"
    );
    let (run_status,): (String,) =
        sqlx::query_as("SELECT status FROM automation_runs WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("run row");
    assert_eq!(run_status, "running", "the run is resumable, not terminal");
    assert!(message_categories(&pool, &tenant).await.is_empty());

    // Recovery: disarm, lease expires, the SAME run resumes.
    fi::disarm(&pool, "crash_ladder").await;
    abandon_event_lease(&pool, &tenant, &event_key).await;
    let recovered = engine.tick().await.expect("recovery tick");
    assert_eq!(recovered.runs_started, 1, "the run resumes (not a new one)");
    assert_eq!(recovered.runs_replayed, 0);
    assert_eq!(recovered.runs_succeeded, 1, "{recovered:?}");

    // The ladder completed without repeating effects:
    assert_eq!(
        contact_tags(&pool, &tenant, contact).await,
        json!(["vip"]),
        "the re-executed tag action must not duplicate the tag"
    );
    let list_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM list_subscribers \
         WHERE list_id = $1 AND contact_id = $2",
    )
    .bind(list_id)
    .bind(contact)
    .fetch_one(&pool)
    .await
    .expect("list membership after resume");
    assert_eq!(list_rows, 1, "the re-executed list action must not duplicate");
    let messages = message_categories(&pool, &tenant).await;
    assert_eq!(messages.len(), 1, "the send happened exactly once");
    assert_eq!(queue_categories(&pool, &tenant).await.len(), 1);
    let actions: Vec<(i32, String)> = sqlx::query_as(
        "SELECT action_index, status FROM automation_run_actions \
         WHERE tenant_id = $1 ORDER BY action_index",
    )
    .bind(&tenant)
    .fetch_all(&pool)
    .await
    .expect("action rows");
    assert_eq!(
        actions,
        vec![
            (0, "succeeded".to_string()),
            (1, "succeeded".to_string()),
            (2, "succeeded".to_string()),
        ],
        "all three actions carry a terminal record"
    );
    let runs = run_rows(&pool, &tenant, automation).await;
    assert_eq!(runs.len(), 1, "still the SAME run");
    assert_eq!(runs[0].0, "succeeded");
    assert_eq!(
        event_status(&pool, &tenant, &event_key).await.as_deref(),
        Some("processed")
    );
    assert_eq!(backend.used(), 1, "quota reserved exactly once");
}

/// Window 3 — crash AFTER the send transaction committed but BEFORE the
/// action bookkeeping was written. The derived message idempotency key
/// (`autoact:{run_id}:{index}`) must make the recovery a no-op re-enqueue:
/// one message, one queue row, one quota reservation across the crash.
#[tokio::test]
async fn crash_between_send_commit_and_bookkeeping_reuses_message_and_quota() {
    let Some(pool) = fresh_pool("autoexec_crash_book").await else {
        return;
    };
    let backend = Arc::new(FakeAdmissionBackend::new());
    let engine = executor(&pool, backend.clone());

    let tenant = fresh_tenant();
    insert_tenant(&pool, &tenant).await;
    let domain = insert_domain(&pool, &tenant).await;
    let template = insert_template(&pool, &tenant).await;
    let automation = insert_automation(
        &pool,
        &tenant,
        "Crash after commit",
        json!({"type": "event", "event": "contact.created"}),
        json!({}),
        send_email_action(&format!("welcome@{domain}"), &template),
    )
    .await;
    let contact = insert_contact(&pool, &tenant, "crash-book@example.com", &[]).await;
    let event_key = format!("contact.created:{contact}");

    // The send's `messages` + `email_queue` transaction commits, admission is
    // reserved, then the FIRST bookkeeping statement raises: process death
    // with the message already enqueued.
    fi::arm_write_fault(&pool, "automation_run_actions", "crash_book", 0).await;
    assert!(engine.tick().await.is_err(), "the fault kills the tick");

    let messages = message_categories(&pool, &tenant).await;
    assert_eq!(messages.len(), 1, "the send committed before the crash");
    assert_eq!(queue_categories(&pool, &tenant).await.len(), 1);
    assert!(action_rows(&pool, &tenant).await.is_empty(), "bookkeeping lost");
    assert_eq!(backend.used(), 1, "the quota reserve is orphaned, not rolled back");
    let (run_status,): (String,) =
        sqlx::query_as("SELECT status FROM automation_runs WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("run row");
    assert_eq!(run_status, "running");

    // Recovery: the retry re-admits through the SAME derived quota identity
    // and re-inserts through the SAME derived message idempotency key.
    fi::disarm(&pool, "crash_book").await;
    abandon_event_lease(&pool, &tenant, &event_key).await;
    let recovered = engine.tick().await.expect("recovery tick");
    assert_eq!(recovered.runs_started, 1, "the run resumes");
    assert_eq!(recovered.runs_succeeded, 1, "{recovered:?}");

    let messages = message_categories(&pool, &tenant).await;
    assert_eq!(
        messages.len(),
        1,
        "the idempotency key must reuse the committed message, never send again"
    );
    assert_eq!(
        queue_categories(&pool, &tenant).await.len(),
        1,
        "the duplicate branch must not add a second queue row"
    );
    let actions = action_rows(&pool, &tenant).await;
    assert_eq!(actions.len(), 1, "the action record was restored");
    assert_eq!(actions[0].1, "succeeded");
    assert_eq!(
        actions[0].4["duplicate"], true,
        "the recovery went through the derived idempotency key: {:?}",
        actions[0].4
    );
    let runs = run_rows(&pool, &tenant, automation).await;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].0, "succeeded");
    assert_eq!(
        event_status(&pool, &tenant, &event_key).await.as_deref(),
        Some("processed")
    );
    // One quota unit across crash + recovery: the second admission hit the
    // same deterministic event id and was a duplicate.
    assert_eq!(backend.used(), 1, "quota counted exactly once");
    assert_eq!(
        backend.reserves(),
        2,
        "both attempts called admission; the dedup key arbitrated"
    );
}
