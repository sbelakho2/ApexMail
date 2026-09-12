//! Production dispatcher integration tests on the surviving sequence path.
//!
//! The second campaign send engine (`CampaignEmailDispatcher`,
//! `CampaignManager::with_email_dispatcher`, `scheduler::process_campaign`,
//! `due_recipients`) was deleted by the one-send-engine refactor. Every test
//! below keeps its ORIGINAL subject matter but exercises it through the one
//! path that exists:
//!
//! `sales_actions` (leased, fenced) → `SequenceStepHandler` →
//! `decision_engine::decide` → `ProductionCampaignDispatcher::enqueue_sequenced`
//! → `messages` + `email_queue`.
//!
//! Mapping notes:
//! * the send ledger is now `sales_step_executions` (state `sent`/`skipped`)
//!   plus the `messages` idempotency key
//!   `sa:{enrollment}:{version}:{step}:{attempt_kind}:{variant}` — NOT the
//!   campaign `sacmp:{campaign}:{recipient}` key;
//! * "the scheduler completes the campaign" no longer exists
//!   (`scheduler::run`/`tick`/`process_campaign` removed with the engine); the
//!   surviving completion behaviour is enrollment advancement, asserted here;
//! * "quota exhaustion pauses the campaign with an error state" no longer
//!   exists either; the surviving contract is that `enqueue_sequenced`
//!   reserves the same billing quota and refuses without an external effect,
//!   and the action stays retryable (queue bookkeeping is covered by the
//!   `src/actions.rs` tests, e.g. `expired_lease_is_recovered_by_another_worker`);
//! * the campaign-stats reconciliation test was removed: `start_campaign` no
//!   longer links messages to `sales_campaign_recipients`, and
//!   `reconcile_campaign_stats`'s real coverage now lives in
//!   `campaigns::tests::reconcile_sql_counts_sent_events_with_enqueue_fallback`
//!   (pure, default) and
//!   `campaigns::tests::reconcile_sent_counter_follows_events_or_falls_back`
//!   (live, ignored).
//!
//! Run against a real Postgres (soft-skip without one; the live tests are
//! `#[ignore]`d so the default crate run stays database-free); see
//! `common/mod.rs` for the canonical bootstrap and the sequence fixture.

mod common;

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use billing_service::send_admission::{
    AdmissionMeter, SendAdmissionError, SendAdmissionRequest, SendAdmissionService,
};

use sales_autopilot::actions::{ActionOutcome, ActionQueue, LeasedAction};
use sales_autopilot::campaigns::CampaignManager;
use sales_autopilot::dispatcher::{
    send_idempotency_key, EnqueueOutcome, ProductionCampaignDispatcher, RenderedMessage,
    SendIdentity,
};
use sales_autopilot::sender_pool;
use sales_autopilot::types::{SalesError, SenderIdentity, SenderPool};

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/// Deterministic in-memory [`billing_service::send_admission::
/// SendAdmissionBackend`] — the SHARED admission contract (one counter per
/// tenant, usage-event-id de-duplication, all-or-nothing reservation,
/// event-id keyed rollback) with the knobs these tests need.
///
/// Modes:
/// * `new()` — allow everything (limit = -1, billing's "unlimited"),
/// * `with_limit(n)` — allow exactly n reserved units, then quota denial,
/// * `with_transient_failure_at(call)` — the given record call (1-based)
///   fails with an infrastructure error, simulating a billing/DB hiccup,
/// * `suppress(email)` — put an address on the tenant suppression list.
///
/// NOTE: deliberately not `Default` — a derived Default would set limit=0
/// (deny everything); construct via [`FakeAdmissionBackend::new`].
#[derive(Debug)]
struct FakeAdmissionBackend {
    /// -1 = unlimited (billing convention).
    limit: AtomicI64,
    used: AtomicI64,
    transient_fail_at: AtomicI64,
    reserves: AtomicUsize,
    rollbacks: AtomicUsize,
    /// Usage-event-id → reserved quantity (the de-duplication ledger).
    events: std::sync::Mutex<std::collections::HashMap<Uuid, i64>>,
    suppressed: std::sync::Mutex<Vec<String>>,
}

impl FakeAdmissionBackend {
    fn new() -> Self {
        Self {
            limit: AtomicI64::new(-1),
            used: AtomicI64::new(0),
            transient_fail_at: AtomicI64::new(0),
            reserves: AtomicUsize::new(0),
            rollbacks: AtomicUsize::new(0),
            events: std::sync::Mutex::new(std::collections::HashMap::new()),
            suppressed: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn with_limit(limit: i64) -> Self {
        Self {
            limit: AtomicI64::new(limit),
            ..Self::new()
        }
    }

    fn with_transient_failure_at(call: i64) -> Self {
        Self {
            transient_fail_at: AtomicI64::new(call),
            ..Self::new()
        }
    }

    fn rollbacks(&self) -> usize {
        self.rollbacks.load(Ordering::SeqCst)
    }

    fn reserves(&self) -> usize {
        self.reserves.load(Ordering::SeqCst)
    }

    fn used(&self) -> i64 {
        self.used.load(Ordering::SeqCst)
    }

    fn suppress(&self, email: &str) {
        self.suppressed
            .lock()
            .unwrap()
            .push(email.trim().to_ascii_lowercase());
    }
}

#[async_trait::async_trait]
impl billing_service::send_admission::SendAdmissionBackend for FakeAdmissionBackend {
    async fn record_send_usage(
        &self,
        _tenant_id: &str,
        quantity: i64,
        event_id: Uuid,
    ) -> Result<billing_service::usage::QuotaRecordResult, billing_service::usage::UsageError> {
        let n = self.reserves.fetch_add(1, Ordering::SeqCst) as i64 + 1;
        if self.transient_fail_at.load(Ordering::SeqCst) == n {
            return Err(billing_service::usage::UsageError::Audit(
                "simulated billing outage".into(),
            ));
        }
        // The canonical gate de-duplicates by event id BEFORE the limit: a
        // replayed logical send is admitted even at a full counter.
        let mut events = self.events.lock().unwrap();
        if let Some(previous) = events.get(&event_id) {
            assert_eq!(*previous, quantity, "duplicate must carry same quantity");
            return Ok(billing_service::usage::QuotaRecordResult {
                allowed: true,
                current: self.used.load(Ordering::SeqCst),
                duplicate: true,
            });
        }
        let limit = self.limit.load(Ordering::SeqCst);
        let used = self.used.load(Ordering::SeqCst);
        if limit >= 0 && used + quantity > limit {
            // Mirror the Lua semantics: denial does not consume quota.
            return Ok(billing_service::usage::QuotaRecordResult {
                allowed: false,
                current: used,
                duplicate: false,
            });
        }
        self.used.fetch_add(quantity, Ordering::SeqCst);
        events.insert(event_id, quantity);
        Ok(billing_service::usage::QuotaRecordResult {
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
    ) -> Result<(), billing_service::usage::UsageError> {
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
        let mut matches: Vec<String> = canonical_recipients
            .iter()
            .filter(|email| suppressed.contains(email))
            .cloned()
            .collect();
        matches.sort();
        matches.dedup();
        Ok(matches)
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A `ProductionCampaignDispatcher` bound to the canonical sequence fixture.
struct Fixture {
    db: PgPool,
    tenant_id: String,
    seq: common::SequenceFixture,
    dispatcher: Arc<ProductionCampaignDispatcher>,
    admission: Arc<FakeAdmissionBackend>,
}

impl Fixture {
    /// Rebuild the dispatcher around a different admission backend (the tests
    /// that exercise admission accounting replace it mid-test, exactly like
    /// the old suite did).
    fn set_admission(&mut self, admission: Arc<FakeAdmissionBackend>) {
        self.admission = admission;
        self.dispatcher = Arc::new(
            ProductionCampaignDispatcher::new(
                common::test_dispatch_config_for(&self.seq.domain),
                self.db.clone(),
                self.admission.clone(),
            )
            .expect("test dispatch config must be valid"),
        );
    }
}

async fn fixture(test_name: &str, opts: common::SequenceFixtureOptions) -> Option<Fixture> {
    let db = common::test_pool(test_name).await?;
    let tenant_id = common::insert_test_tenant(&db, test_name).await;
    let seq = common::seed_sequence_fixture(&db, &tenant_id, opts).await;
    let admission = Arc::new(FakeAdmissionBackend::new());
    let dispatcher = Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(&seq.domain),
            db.clone(),
            admission.clone(),
        )
        .expect("test dispatch config must be valid"),
    );
    Some(Fixture {
        db,
        tenant_id,
        seq,
        dispatcher,
        admission,
    })
}

fn fixture_options() -> common::SequenceFixtureOptions {
    common::SequenceFixtureOptions::default()
}

/// The expected logical send identity of the fixture's first step.
fn fixture_key(fx: &Fixture) -> String {
    send_idempotency_key(SendIdentity::StepExecution {
        enrollment_id: fx.seq.enrollment_id.expect("fixture enrolls"),
        sequence_version_id: fx.seq.version_id,
        step_id: fx.seq.step_id,
        attempt_kind: "primary",
        variant: "default",
    })
}

fn rendered() -> RenderedMessage {
    RenderedMessage {
        subject: "fixture subject".into(),
        html: Some("<p>fixture html</p>".into()),
        text: Some("fixture text".into()),
    }
}

async fn step_state(db: &PgPool, step_execution_id: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT state, skip_reason FROM sales_step_executions WHERE id = $1")
        .bind(step_execution_id)
        .fetch_one(db)
        .await
        .expect("read step execution")
}

async fn message_count_for_step(db: &PgPool, step_execution_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE sales_step_execution_id = $1")
        .bind(step_execution_id)
        .fetch_one(db)
        .await
        .expect("count messages")
}

async fn queue_count_for_step(db: &PgPool, step_execution_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM email_queue WHERE sales_step_execution_id = $1")
        .bind(step_execution_id)
        .fetch_one(db)
        .await
        .expect("count queue rows")
}

/// Enqueue and claim the step's production action; resolve the sender the
/// sequence worker would use. Returns the live lease and the identity.
async fn live_fence(
    db: &PgPool,
    tenant_id: &str,
    step_execution_id: Uuid,
) -> (LeasedAction, SenderIdentity) {
    let action = common::enqueue_send_step_action(db, tenant_id, step_execution_id).await;
    let worker = format!("dispatcher-test-{}", Uuid::new_v4().simple());
    let leased = common::claim_specific_action(db, &worker, action.id)
        .await
        .expect("the just-enqueued action must be claimable");
    let sender = sender_pool::resolve_sales_sender(db, tenant_id, SenderPool::SalesOutbound)
        .await
        .expect("fixture sender identity resolves");
    (leased, sender)
}

async fn finish_leased(db: &PgPool, leased: &LeasedAction, outcome: ActionOutcome) {
    let queue = ActionQueue::new(db.clone(), leased.lease_owner.clone());
    assert!(
        queue
            .finish(&leased.fence(), outcome)
            .await
            .expect("finish action"),
        "the worker must still own its live lease"
    );
}

#[allow(clippy::too_many_arguments)]
async fn enqueue_step(
    fx: &Fixture,
    key: &str,
    step_execution_id: Uuid,
    enrollment_id: Uuid,
    leased: &LeasedAction,
    sender: &SenderIdentity,
) -> Result<EnqueueOutcome, SalesError> {
    // The typed provenance FK (`fk_messages_sales_decision`, migration 202
    // line 46) requires a real Decision Packet row.
    let decision_id = common::insert_fixture_decision(&fx.db, &fx.tenant_id).await;
    fx.dispatcher
        .enqueue_sequenced(
            &fx.tenant_id,
            key,
            &rendered(),
            &fx.seq.email,
            "https://sales.example.com/u/fixture-token",
            sender,
            decision_id,
            step_execution_id,
            enrollment_id,
            &leased.fence(),
            serde_json::json!({ "enrollment_id": enrollment_id.to_string() }),
        )
        .await
}

// ---------------------------------------------------------------------------
// Happy path: real enqueue through the platform pipeline
// ---------------------------------------------------------------------------

/// The dispatcher's real job is unchanged: enqueue through the platform
/// pipeline with List-Unsubscribe headers, escaped personalization, the
/// compliance footer, typed sales provenance — but the envelope sender is now
/// the RESOLVED sender identity, never the deployment-wide
/// `SALES_CAMPAIGN_FROM_EMAIL` (the defect the sequence path exists to fix).
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn sequence_step_send_enqueues_into_the_platform_pipeline() {
    // The identity sends from a SECOND verified domain, distinct from the
    // dispatcher config's deployment-wide sender.
    let identity_domain = common::unique_test_domain();
    let Some(fx) = fixture(
        "sequence_pipeline",
        fixture_options().with_identity_domain(identity_domain.clone()),
    )
    .await
    else {
        return;
    };
    let db = fx.db.clone();
    let tenant = fx.tenant_id.clone();
    let seq = fx.seq.clone();
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");
    let enrollment_id = seq.enrollment_id.expect("fixture enrolls");

    // Hostile personalization data on the canonical contact/account. The
    // rendered body now comes from the strategy planner, whose personalization
    // sink is the account's `company` (the contact name is not interpolated):
    // a live hiring signal makes `derive_problem_hypothesis` use that field,
    // so the hostile value actually reaches the body and the escaping gate is
    // genuinely exercised rather than asserted vacuously.
    sqlx::query("UPDATE sales_contacts SET full_name = $2 WHERE id = $1")
        .bind(seq.contact_id)
        .bind("<script>alert('xss')</script>")
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("UPDATE sales_accounts SET company = $2 WHERE id = $1")
        .bind(seq.account_id)
        .bind("ACME & Sons <script>alert('xss')</script>")
        .execute(&db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sales_signals (id, tenant_id, account_id, signal_type, strength, \
         observed_at, payload) \
         VALUES (gen_random_uuid(), $1, $2, 'hiring_growth', 0.95, NOW(), '{}'::jsonb)",
    )
    .bind(&tenant)
    .bind(seq.account_id)
    .execute(&db)
    .await
    .unwrap();

    let outcome =
        common::run_send_step(&db, fx.dispatcher.clone(), &tenant, step_execution_id).await;
    assert!(
        matches!(outcome, ActionOutcome::Succeeded),
        "fixture must send: {outcome:?}"
    );

    // `messages`: one row, the canonical step-execution idempotency key (NOT
    // `sacmp:...`), status queued, envelope = resolved identity.
    let messages: Vec<(
        String,
        String,
        String,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT idempotency_key, status, from_email, sales_step_execution_id, \
                sales_enrollment_id, sales_decision_id, sales_sender_identity_id, \
                to_emails->>0 \
         FROM messages WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(messages.len(), 1, "one messages row per step execution");
    let (key, status, from_email, msg_step, msg_enrollment, msg_decision, msg_sender, recipient) =
        &messages[0];
    assert_eq!(key, &fixture_key(&fx), "logical step identity");
    assert!(
        key.starts_with(&format!(
            "sa:{enrollment_id}:{version}:",
            version = seq.version_id
        )),
        "key namespace is the step execution: {key}"
    );
    assert_eq!(status, "queued");
    assert_eq!(
        from_email,
        &format!("sales@{identity_domain}"),
        "the RESOLVED identity must be the envelope sender"
    );
    assert_ne!(
        from_email,
        &fx.dispatcher.config().from_email,
        "the deployment-wide SALES_CAMPAIGN_FROM_EMAIL must not be the sender"
    );
    assert_eq!(msg_step, &Some(step_execution_id));
    assert_eq!(msg_enrollment, &Some(enrollment_id));
    assert!(msg_decision.is_some(), "a Decision Packet must be linked");
    assert_eq!(msg_sender, &seq.sender_id);
    assert_eq!(recipient.as_deref(), Some(seq.email.as_str()));

    // The Decision Packet records the enforcement verdict and the sender used.
    let (enforcement, selected_sender): (Option<String>, Option<Uuid>) =
        sqlx::query_as("SELECT enforcement, selected_sender_id FROM sales_decisions WHERE id = $1")
            .bind(msg_decision.unwrap())
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(enforcement.as_deref(), Some("execute"));
    assert_eq!(selected_sender, seq.sender_id);

    // `email_queue`: pending, single recipient, RFC 2369 + RFC 8058 headers,
    // typed provenance, campaign_id NULL (sequence mail is attributed to a
    // step execution, not a campaign).
    let queue: Vec<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
    )> = sqlx::query_as(
        "SELECT \"to\", status, headers->>'List-Unsubscribe', \
                headers->>'List-Unsubscribe-Post', sales_step_execution_id, \
                sales_enrollment_id, sales_decision_id, campaign_id \
         FROM email_queue WHERE tenant_id = $1",
    )
    .bind(&tenant)
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(queue.len(), 1);
    let (to, q_status, list_unsub, post, q_step, q_enrollment, q_decision, campaign_id) = &queue[0];
    assert_eq!(to, &seq.email);
    assert_eq!(q_status, "pending");
    let link = list_unsub
        .as_ref()
        .expect("List-Unsubscribe header present");
    assert!(
        link.starts_with('<') && link.ends_with('>'),
        "RFC 2369 angle form: {link}"
    );
    assert!(
        link.contains("/u/"),
        "points at the unsubscribe endpoint: {link}"
    );
    assert_eq!(post.as_deref(), Some("List-Unsubscribe=One-Click"));
    assert_eq!(q_step, &Some(step_execution_id));
    assert_eq!(q_enrollment, &Some(enrollment_id));
    assert_eq!(q_decision, msg_decision);
    assert_eq!(campaign_id, &None);

    // The strategy body is plain text rendered through `compose_reply_html`:
    // every interpolated lead/account value must be HTML-escaped, and raw
    // markup must never appear. The compliance footer rides along.
    let (subject, html): (String, Option<String>) = sqlx::query_as(
        "SELECT subject, html_body FROM messages WHERE idempotency_key = $1 AND tenant_id = $2",
    )
    .bind(key)
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .unwrap();
    let html = html.expect("html part");
    assert!(
        html.contains("ACME &amp; Sons &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"),
        "hostile account personalization must be HTML-escaped: {html}"
    );
    assert!(
        !html.contains("<script>alert"),
        "raw script must never appear"
    );
    assert!(
        html.contains("ACME &amp; Sons"),
        "company ampersand escaped"
    );
    assert!(html.contains("Unsubscribe</a>"), "footer unsubscribe link");
    // The strategy subject is composed from server-owned constants and never
    // interpolates lead data, so hostile markup (raw or entity-encoded) must
    // not be able to ride out in it.
    assert!(
        !subject.contains("<script") && !subject.contains("&lt;script"),
        "subject must not carry hostile personalization: {subject}"
    );

    // The send ledger is the step execution; the enrollment advanced to
    // completion (single-step sequence).
    let (state, _) = step_state(&db, step_execution_id).await;
    assert_eq!(state, "sent");
    let enrollment_state: String =
        sqlx::query_scalar("SELECT state FROM sales_enrollments WHERE id = $1")
            .bind(enrollment_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        enrollment_state, "completed",
        "the last step completes the enrollment"
    );

    common::cleanup_tenant(&db, &tenant).await;
}

// ---------------------------------------------------------------------------
// Non-happy-path: suppression
// ---------------------------------------------------------------------------

/// A platform suppression (the table the delivery worker writes hard bounces
/// and complaints into) recorded after the recipient was selected must stop
/// the send at the Decision Packet.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn platform_suppression_after_selection_blocks_the_send() {
    let Some(fx) = fixture("sequence_suppression", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");

    sqlx::query(
        "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at) \
         VALUES ($1, $2, $3, 'hard_bounce', 'worker', NOW())",
    )
    .bind(apexmail_lib::id::generate_id("sup", 22))
    .bind(&fx.tenant_id)
    .bind(&fx.seq.email)
    .execute(&fx.db)
    .await
    .unwrap();

    let outcome = common::run_send_step(
        &fx.db,
        fx.dispatcher.clone(),
        &fx.tenant_id,
        step_execution_id,
    )
    .await;
    assert!(
        matches!(outcome, ActionOutcome::Succeeded),
        "a denial is a recorded skip, not a retry: {outcome:?}"
    );
    let (state, skip_reason) = step_state(&fx.db, step_execution_id).await;
    assert_eq!(state, "skipped");
    assert!(
        skip_reason.as_deref().unwrap_or("").contains("suppressed"),
        "the refusal must name the suppression: {skip_reason:?}"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 0);
    assert_eq!(queue_count_for_step(&fx.db, step_execution_id).await, 0);

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

/// Suppression is tenant-scoped: another tenant's opt-out row for the SAME
/// address must not refuse this tenant's send. (The old suite asserted tenant
/// isolation on the campaign and inbox paths; this pins it on the send gate.)
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn suppression_is_tenant_scoped_for_the_send_recheck() {
    let Some(fx) = fixture("sequence_tenant_scope", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");
    let other_tenant = common::insert_test_tenant(&fx.db, "sequence-other").await;

    sqlx::query(
        "INSERT INTO sales_unsubscribes (tenant_id, email) VALUES ($1, lower($2)) \
         ON CONFLICT (tenant_id, email) DO NOTHING",
    )
    .bind(&other_tenant)
    .bind(&fx.seq.email)
    .execute(&fx.db)
    .await
    .unwrap();

    let outcome = common::run_send_step(
        &fx.db,
        fx.dispatcher.clone(),
        &fx.tenant_id,
        step_execution_id,
    )
    .await;
    assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");
    let (state, _) = step_state(&fx.db, step_execution_id).await;
    assert_eq!(
        state, "sent",
        "another tenant's row must not block this send"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 1);

    common::cleanup_tenant(&fx.db, &other_tenant).await;
    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

/// The dispatcher's transactional pre-send recheck (the old
/// `enqueue_recipient` behaviour): a suppression that lands between the
/// decision and the enqueue is still honoured, nothing is written, and the
/// quota reservation is released.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn suppression_landing_between_decision_and_enqueue_is_refused() {
    let Some(fx) = fixture("sequence_suppression_race", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");
    let enrollment_id = fx.seq.enrollment_id.expect("fixture enrolls");
    let key = fixture_key(&fx);
    let (leased, sender) = live_fence(&fx.db, &fx.tenant_id, step_execution_id).await;

    // Suppression lands AFTER the action was claimed/decided but BEFORE the
    // enqueue transaction.
    sqlx::query(
        "INSERT INTO sales_unsubscribes (tenant_id, email) VALUES ($1, lower($2)) \
         ON CONFLICT (tenant_id, email) DO NOTHING",
    )
    .bind(&fx.tenant_id)
    .bind(&fx.seq.email)
    .execute(&fx.db)
    .await
    .unwrap();

    let outcome = enqueue_step(
        &fx,
        &key,
        step_execution_id,
        enrollment_id,
        &leased,
        &sender,
    )
    .await;
    assert_eq!(
        outcome.expect("the recheck is a graceful refusal, not an error"),
        EnqueueOutcome::AlreadyClaimed,
        "the in-transaction recheck must refuse the suppressed recipient"
    );
    assert!(
        fx.admission.rollbacks() >= 1,
        "no quota may leak on a refusal"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 0);
    assert_eq!(queue_count_for_step(&fx.db, step_execution_id).await, 0);
    finish_leased(&fx.db, &leased, ActionOutcome::Succeeded).await;

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

// ---------------------------------------------------------------------------
// Non-happy-path: crash-restart idempotency (never double-send)
// ---------------------------------------------------------------------------

/// Crash/restart must never double-send. Two layers are asserted:
/// 1. a crashed worker that left the step in `executing` cannot enqueue again
///    when its action is replayed (the step-claim guard);
/// 2. replaying the same logical step execution through the dispatcher hits
///    the idempotency key and is a no-op that consumes no additional quota
///    (the deterministic `sa-send:{step_execution_id}` usage identity is
///    recognized as a duplicate, and a duplicate owns no reservation to
///    release — releasing it would delete the winner's);
/// 3. a DIFFERENT step for the same recipient is a different logical send and
///    does produce a second message — the regression the key change exists
///    for.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn crash_replay_never_double_sends_but_a_second_step_is_a_new_send() {
    let Some(fx) = fixture("sequence_crash_replay", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");
    let enrollment_id = fx.seq.enrollment_id.expect("fixture enrolls");
    let template_id = fx.seq.template_id.clone().expect("fixture template");
    let key = fixture_key(&fx);

    // A real economic basis for the account: the first handler run persists a
    // score, and without an open pipeline amount plus live evidence that
    // stored score has a negative expected value, so the SECOND step would be
    // refused by the §28 next-best-action gate before it could be a send.
    // This test's subject is crash/restart exactly-once, not the economic
    // gate, so seed the basis the planner docs require.
    common::seed_open_opportunity(&fx.db, &fx.tenant_id, fx.seq.account_id, 100_000.0).await;
    common::seed_live_evidence(&fx.db, &fx.tenant_id, fx.seq.account_id, 3).await;

    // First send succeeds.
    let first = common::run_send_step(
        &fx.db,
        fx.dispatcher.clone(),
        &fx.tenant_id,
        step_execution_id,
    )
    .await;
    assert!(matches!(first, ActionOutcome::Succeeded), "{first:?}");
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 1);

    // Crash window: the worker enqueued, then died before stamping the step
    // and advancing the enrollment.
    sqlx::query("UPDATE sales_step_executions SET state = 'executing' WHERE id = $1")
        .bind(step_execution_id)
        .execute(&fx.db)
        .await
        .unwrap();
    sqlx::query("UPDATE sales_enrollments SET state = 'active', completed_at = NULL WHERE id = $1")
        .bind(enrollment_id)
        .execute(&fx.db)
        .await
        .unwrap();
    // Recovery requeues the action (what lease expiry does).
    sqlx::query(
        "UPDATE sales_actions SET state = 'queued', due_at = NOW(), lease_owner = NULL, \
                lease_token = NULL, lease_expires_at = NULL, completed_at = NULL \
         WHERE entity_type = 'step_execution' AND entity_id = $1",
    )
    .bind(step_execution_id)
    .execute(&fx.db)
    .await
    .unwrap();

    let replay = common::run_send_step(
        &fx.db,
        fx.dispatcher.clone(),
        &fx.tenant_id,
        step_execution_id,
    )
    .await;
    assert!(
        matches!(replay, ActionOutcome::Succeeded),
        "an in-flight step must not enqueue again: {replay:?}"
    );
    assert_eq!(
        message_count_for_step(&fx.db, step_execution_id).await,
        1,
        "still exactly one messages row"
    );
    assert_eq!(
        queue_count_for_step(&fx.db, step_execution_id).await,
        1,
        "still exactly one queue row"
    );

    // Dispatcher-level replay of the same logical step execution.
    sqlx::query(
        "UPDATE sales_actions SET state = 'queued', due_at = NOW(), lease_owner = NULL, \
                lease_token = NULL, lease_expires_at = NULL, completed_at = NULL \
         WHERE entity_type = 'step_execution' AND entity_id = $1",
    )
    .bind(step_execution_id)
    .execute(&fx.db)
    .await
    .unwrap();
    let (leased, sender) = live_fence(&fx.db, &fx.tenant_id, step_execution_id).await;
    let duplicate = enqueue_step(
        &fx,
        &key,
        step_execution_id,
        enrollment_id,
        &leased,
        &sender,
    )
    .await;
    assert_eq!(
        duplicate.expect("duplicate detection is graceful"),
        EnqueueOutcome::DuplicateIdempotency,
        "the same logical step must never enqueue twice"
    );
    assert_eq!(
        fx.admission.used(),
        1,
        "the duplicate admission reserves nothing extra"
    );
    assert_eq!(
        fx.admission.rollbacks(),
        0,
        "a duplicate owns no reservation and must NOT release the winner's (F22)"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 1);
    finish_leased(&fx.db, &leased, ActionOutcome::Succeeded).await;

    // A second step for the SAME recipient is a different logical send.
    let step2 =
        common::add_email_step(&fx.db, &fx.tenant_id, fx.seq.version_id, 1, &template_id).await;
    let exec2 = common::seed_step_execution(
        &fx.db,
        &fx.tenant_id,
        enrollment_id,
        fx.seq.version_id,
        step2,
        1,
    )
    .await;
    let second = common::run_send_step(&fx.db, fx.dispatcher.clone(), &fx.tenant_id, exec2).await;
    assert!(matches!(second, ActionOutcome::Succeeded), "{second:?}");
    assert_eq!(
        message_count_for_step(&fx.db, exec2).await,
        1,
        "a second step for the same recipient must be representable"
    );
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT idempotency_key FROM messages WHERE tenant_id = $1 ORDER BY idempotency_key",
    )
    .bind(&fx.tenant_id)
    .fetch_all(&fx.db)
    .await
    .unwrap();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1], "each step has its own send identity");

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

// ---------------------------------------------------------------------------
// Non-happy-path: quota exhaustion
// ---------------------------------------------------------------------------

/// Quota exhaustion refuses the send with no external effect and no leak;
/// restoring quota lets the SAME live action enqueue. The old "campaign pauses
/// with an error state" half of this test was scheduler behaviour
/// (`scheduler::process_campaign` is removed with the engine); the surviving
/// caller contract is a retryable action — see the module docs.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn quota_exhaustion_refuses_the_send_and_recovers() {
    let Some(mut fx) = fixture("sequence_quota", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");
    let enrollment_id = fx.seq.enrollment_id.expect("fixture enrolls");
    let template_id = fx.seq.template_id.clone().expect("fixture template");
    let step2 =
        common::add_email_step(&fx.db, &fx.tenant_id, fx.seq.version_id, 1, &template_id).await;
    let exec2 = common::seed_step_execution(
        &fx.db,
        &fx.tenant_id,
        enrollment_id,
        fx.seq.version_id,
        step2,
        1,
    )
    .await;

    // Exactly one recipient fits the quota.
    fx.set_admission(Arc::new(FakeAdmissionBackend::with_limit(1)));
    let key1 = fixture_key(&fx);
    let key2 = send_idempotency_key(SendIdentity::StepExecution {
        enrollment_id,
        sequence_version_id: fx.seq.version_id,
        step_id: step2,
        attempt_kind: "primary",
        variant: "default",
    });

    let (leased1, sender1) = live_fence(&fx.db, &fx.tenant_id, step_execution_id).await;
    let first = enqueue_step(
        &fx,
        &key1,
        step_execution_id,
        enrollment_id,
        &leased1,
        &sender1,
    )
    .await
    .expect("first recipient fits the quota");
    assert_eq!(first, EnqueueOutcome::Enqueued);
    finish_leased(&fx.db, &leased1, ActionOutcome::Succeeded).await;

    let (leased2, sender2) = live_fence(&fx.db, &fx.tenant_id, exec2).await;
    let denied = enqueue_step(&fx, &key2, exec2, enrollment_id, &leased2, &sender2).await;
    assert!(
        matches!(denied, Err(SalesError::QuotaExhausted(_))),
        "quota exhaustion must surface, got {denied:?}"
    );
    assert!(
        fx.admission.reserves() >= 2,
        "denied reserves were attempted"
    );
    assert_eq!(message_count_for_step(&fx.db, exec2).await, 0);
    assert_eq!(queue_count_for_step(&fx.db, exec2).await, 0);

    // Quota restored: the SAME still-live fence retries successfully (the
    // denial consumed nothing).
    fx.set_admission(Arc::new(FakeAdmissionBackend::new()));
    let retried = enqueue_step(&fx, &key2, exec2, enrollment_id, &leased2, &sender2).await;
    assert_eq!(
        retried.expect("retry after recovery"),
        EnqueueOutcome::Enqueued
    );
    assert_eq!(message_count_for_step(&fx.db, exec2).await, 1);
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 1);
    finish_leased(&fx.db, &leased2, ActionOutcome::Succeeded).await;

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

// ---------------------------------------------------------------------------
// Non-happy-path: transient quota failure → retried, idempotently
// ---------------------------------------------------------------------------

/// A transient reserve failure mid-batch leaves the earlier recipient
/// enqueued, the failed one untouched, and a retry after recovery enqueues it
/// exactly once. The old campaign status assertions ("active" through the
/// failure, "completed" after the tick) belonged to the removed scheduler; the
/// surviving equivalent is the idempotent action retry asserted here.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn transient_quota_failure_is_retried_without_duplicates() {
    let Some(mut fx) = fixture("sequence_quota_transient", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");
    let enrollment_id = fx.seq.enrollment_id.expect("fixture enrolls");
    let template_id = fx.seq.template_id.clone().expect("fixture template");
    let step2 =
        common::add_email_step(&fx.db, &fx.tenant_id, fx.seq.version_id, 1, &template_id).await;
    let exec2 = common::seed_step_execution(
        &fx.db,
        &fx.tenant_id,
        enrollment_id,
        fx.seq.version_id,
        step2,
        1,
    )
    .await;
    let key1 = fixture_key(&fx);
    let key2 = send_idempotency_key(SendIdentity::StepExecution {
        enrollment_id,
        sequence_version_id: fx.seq.version_id,
        step_id: step2,
        attempt_kind: "primary",
        variant: "default",
    });

    // The SECOND reserve call fails transiently: recipient 1 enqueues, then
    // the batch aborts.
    fx.set_admission(Arc::new(FakeAdmissionBackend::with_transient_failure_at(2)));
    let (leased1, sender1) = live_fence(&fx.db, &fx.tenant_id, step_execution_id).await;
    assert_eq!(
        enqueue_step(
            &fx,
            &key1,
            step_execution_id,
            enrollment_id,
            &leased1,
            &sender1
        )
        .await
        .expect("first recipient enqueues"),
        EnqueueOutcome::Enqueued
    );
    finish_leased(&fx.db, &leased1, ActionOutcome::Succeeded).await;

    let (leased2, sender2) = live_fence(&fx.db, &fx.tenant_id, exec2).await;
    let failed = enqueue_step(&fx, &key2, exec2, enrollment_id, &leased2, &sender2).await;
    assert!(
        matches!(failed, Err(SalesError::ServiceUnavailable(_))),
        "transient failure surfaces, got {failed:?}"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 1);
    assert_eq!(message_count_for_step(&fx.db, exec2).await, 0);
    assert_eq!(queue_count_for_step(&fx.db, exec2).await, 0);

    // Health restored: retry the failed step, then replay it — one row each.
    fx.set_admission(Arc::new(FakeAdmissionBackend::new()));
    assert_eq!(
        enqueue_step(&fx, &key2, exec2, enrollment_id, &leased2, &sender2)
            .await
            .expect("retry after recovery"),
        EnqueueOutcome::Enqueued
    );
    assert_eq!(
        message_count_for_step(&fx.db, exec2).await,
        1,
        "no duplicates"
    );
    let replay = enqueue_step(&fx, &key2, exec2, enrollment_id, &leased2, &sender2).await;
    assert_eq!(
        replay.expect("replay is graceful"),
        EnqueueOutcome::DuplicateIdempotency
    );
    // The deterministic usage identity collapses the replay onto the
    // winner's metering event: no extra unit, and the duplicate must not
    // release the winner's reservation (F22).
    assert_eq!(fx.admission.used(), 1, "replay reserves nothing extra");
    assert_eq!(fx.admission.rollbacks(), 0, "replay releases nothing");
    assert_eq!(message_count_for_step(&fx.db, exec2).await, 1);
    finish_leased(&fx.db, &leased2, ActionOutcome::Succeeded).await;

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

// ---------------------------------------------------------------------------
// Audit implementation-order item 3: ONE admission gate across send paths
// ---------------------------------------------------------------------------

/// A REST-shaped reservation and a sales send must consume the SAME tenant
/// counter on the SAME admission backend: after the REST reservation, the
/// sales send sees the decrement (it fits only because the shared limit is
/// two), and once the sales unit is taken the REST-shaped gate is refused.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn sales_send_consumes_the_same_quota_the_rest_path_consumes() {
    let Some(mut fx) = fixture("sequence_shared_quota", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");
    let backend = Arc::new(FakeAdmissionBackend::with_limit(2));
    fx.set_admission(backend.clone());
    let service = SendAdmissionService::new(backend.clone());

    // REST-shaped reservation: fixed quantity, HTTP-idempotency-key
    // identity, no suppression filter (`Quantity`, exactly like
    // messages.rs::reserve_email_quota).
    let rest = service
        .admit(SendAdmissionRequest {
            tenant_id: &fx.tenant_id,
            meter: AdmissionMeter::Quantity(1),
            idempotency_key: Some("http-idempotency-key-rest-shaped"),
            idempotency_item: None,
            category: None,
        })
        .await
        .expect("the first REST-shaped unit fits the shared quota");
    rest.commit();
    assert_eq!(backend.used(), 1, "REST took one unit");

    // The sales send must observe that decrement: with limit 2 it fits on
    // the shared counter, consuming the second unit.
    let outcome = common::run_send_step(
        &fx.db,
        fx.dispatcher.clone(),
        &fx.tenant_id,
        step_execution_id,
    )
    .await;
    assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");
    assert_eq!(
        backend.used(),
        2,
        "the sales send consumed the SAME tenant counter the REST path did"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 1);

    // And the shared counter is now genuinely exhausted for BOTH paths: a
    // further REST-shaped reservation is refused.
    let refused = service
        .admit(SendAdmissionRequest {
            tenant_id: &fx.tenant_id,
            meter: AdmissionMeter::Quantity(1),
            idempotency_key: Some("http-idempotency-key-rest-shaped-2"),
            idempotency_item: None,
            category: None,
        })
        .await
        .expect_err("the exhausted shared quota must refuse the REST-shaped send");
    assert!(matches!(refused, SendAdmissionError::QuotaExceeded));

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

/// With the shared quota already consumed by a REST-shaped reservation, a
/// sales send is refused as a RETRYABLE deferral: the worker's error path
/// requeues the action, and NO message or queue row is written.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn sales_send_without_quota_defers_retryably_and_writes_no_message() {
    let Some(mut fx) = fixture("sequence_quota_defer", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");
    let backend = Arc::new(FakeAdmissionBackend::with_limit(1));
    fx.set_admission(backend.clone());
    let service = SendAdmissionService::new(backend.clone());

    service
        .admit(SendAdmissionRequest {
            tenant_id: &fx.tenant_id,
            meter: AdmissionMeter::Quantity(1),
            idempotency_key: Some("http-idempotency-key-exhausts"),
            idempotency_item: None,
            category: None,
        })
        .await
        .expect("the REST-shaped unit fits")
        .commit();
    assert_eq!(backend.used(), 1);

    let outcome = common::run_send_step(
        &fx.db,
        fx.dispatcher.clone(),
        &fx.tenant_id,
        step_execution_id,
    )
    .await;
    assert!(
        matches!(outcome, ActionOutcome::Retry(_)),
        "a quota refusal must be a retryable deferral, got {outcome:?}"
    );
    assert_eq!(backend.used(), 1, "a refused admission reserves nothing");
    assert_eq!(
        message_count_for_step(&fx.db, step_execution_id).await,
        0,
        "no message may be written without quota"
    );
    assert_eq!(
        queue_count_for_step(&fx.db, step_execution_id).await,
        0,
        "no queue row may be written without quota"
    );

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

/// A recipient on the canonical suppression list is refused by admission
/// BEFORE the enqueue transaction: NON-RETRYABLE (the step is cancelled, the
/// action succeeds — it must never be requeued), no message, no queue row,
/// no quota consumed.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn suppressed_recipient_is_refused_non_retryably_on_the_sales_path() {
    let Some(fx) = fixture("sequence_suppressed_admission", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");

    // Canonical suppression list (the shared admission lookup), NOT the
    // sales-local unsubscribe store.
    fx.admission.suppress(&fx.seq.email);

    let outcome = common::run_send_step(
        &fx.db,
        fx.dispatcher.clone(),
        &fx.tenant_id,
        step_execution_id,
    )
    .await;
    assert!(
        matches!(outcome, ActionOutcome::Succeeded),
        "a suppression refusal is a terminal skip, never a retry: {outcome:?}"
    );
    let (state, _) = step_state(&fx.db, step_execution_id).await;
    assert_eq!(
        state, "cancelled",
        "the step must be terminally cancelled, not left retryable"
    );
    assert_eq!(
        fx.admission.used(),
        0,
        "a suppressed recipient consumes no quota"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 0);
    assert_eq!(queue_count_for_step(&fx.db, step_execution_id).await, 0);

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

// ---------------------------------------------------------------------------
// Non-happy-path: sender-domain readiness
// ---------------------------------------------------------------------------

/// Without the verified/DKIM-ready platform domain for the resolved sender,
/// the enqueue transaction refuses; nothing is written and the reservation is
/// released.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn unverified_sender_domain_refuses_dispatch() {
    let Some(fx) = fixture(
        "sequence_unverified_domain",
        fixture_options().without_verified_domain(),
    )
    .await
    else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");
    let enrollment_id = fx.seq.enrollment_id.expect("fixture enrolls");
    let key = fixture_key(&fx);
    let (leased, sender) = live_fence(&fx.db, &fx.tenant_id, step_execution_id).await;

    let err = enqueue_step(
        &fx,
        &key,
        step_execution_id,
        enrollment_id,
        &leased,
        &sender,
    )
    .await
    .expect_err("an unverified sender domain must refuse");
    assert!(
        matches!(err, SalesError::InvalidInput(_)),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains("sender domain"),
        "error must name the sender-domain problem: {err}"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 0);
    assert_eq!(queue_count_for_step(&fx.db, step_execution_id).await, 0);
    assert!(
        fx.admission.rollbacks() >= 1,
        "the refused enqueue must release its reservation"
    );
    assert_eq!(
        fx.admission.used(),
        0,
        "a rolled-back reservation consumes no shared quota"
    );
    let (state, _) = step_state(&fx.db, step_execution_id).await;
    assert_eq!(state, "scheduled", "the step must remain retryable");
    finish_leased(
        &fx.db,
        &leased,
        ActionOutcome::Retry("sender domain missing".into()),
    )
    .await;

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

// ---------------------------------------------------------------------------
// Non-happy-path: missing template
// ---------------------------------------------------------------------------

/// A step whose template does not exist is a RECORDED skip
/// (`skip_reason` names it), not an enqueue and not a retry loop. The old
/// campaign path raised an error out of `start_campaign`; on the canonical
/// path a missing template is a per-step poison condition, so it skips.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn missing_template_is_a_recorded_skip_without_enqueueing() {
    let Some(fx) = fixture(
        "sequence_missing_template",
        fixture_options().without_template(),
    )
    .await
    else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");

    sqlx::query("UPDATE sales_sequence_steps SET template_id = 'tpl_does_not_exist' WHERE id = $1")
        .bind(fx.seq.step_id)
        .execute(&fx.db)
        .await
        .unwrap();

    let outcome = common::run_send_step(
        &fx.db,
        fx.dispatcher.clone(),
        &fx.tenant_id,
        step_execution_id,
    )
    .await;
    assert!(
        matches!(outcome, ActionOutcome::Succeeded),
        "a missing template is a recorded skip: {outcome:?}"
    );
    let (state, skip_reason) = step_state(&fx.db, step_execution_id).await;
    assert_eq!(state, "skipped");
    assert!(
        skip_reason.as_deref().unwrap_or("").contains("template"),
        "the skip reason must name the template: {skip_reason:?}"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 0);
    assert_eq!(queue_count_for_step(&fx.db, step_execution_id).await, 0);

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

// ---------------------------------------------------------------------------
// Dry-run: renders + validates WITHOUT enqueueing
// ---------------------------------------------------------------------------

/// The legacy compatibility planner's dry-run survives the engine removal:
/// it renders and evaluates the legacy recipient funnel against the production
/// dispatcher's sender config without enqueueing or stamping the ledger.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn dry_run_renders_without_enqueueing() {
    let Some(db) = common::test_pool("dry_run").await else {
        return;
    };
    let tenant_id = common::insert_test_tenant(&db, "dry-run").await;
    let domain = common::unique_test_domain();
    common::insert_verified_domain(&db, &tenant_id, &domain).await;
    let dispatcher = Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(&domain),
            db.clone(),
            Arc::new(FakeAdmissionBackend::new()),
        )
        .unwrap(),
    );
    let manager = CampaignManager::new(50, db.clone());

    let template_id = common::insert_template(
        &db,
        &tenant_id,
        "Hi {{first_name}}",
        "<html><body><p>Hello {{first_name}}</p></body></html>",
        Some("Hello {{name}}, plain text."),
    )
    .await;
    let campaign = manager
        .create_campaign(
            tenant_id.clone(),
            "Dry run".into(),
            template_id,
            String::new(),
        )
        .await
        .unwrap();
    manager
        .add_recipients(
            &tenant_id,
            campaign.id,
            vec![
                "alice@example.com".into(),
                "bob@example.com".into(),
                "gone@example.com".into(),
            ],
        )
        .await
        .unwrap();
    manager
        .suppress_recipient(&tenant_id, "gone@example.com")
        .await
        .unwrap();

    let report = manager
        .dry_run(&tenant_id, campaign.id, 5, Some(dispatcher.as_ref()))
        .await
        .unwrap();

    assert_eq!(report["dry_run"], true);
    assert_eq!(report["recipients"]["total"], 3);
    assert_eq!(report["recipients"]["due"], 2);
    assert_eq!(report["recipients"]["suppressed_local"], 1);
    assert_eq!(report["sender"]["domain_verified"], true);
    assert_eq!(report["template"]["has_html"], true);
    let preview = report["preview"].as_array().unwrap();
    assert_eq!(preview.len(), 2, "preview renders due recipients only");
    assert!(preview
        .iter()
        .all(|p| p["subject"].as_str().unwrap().starts_with("Hi ")));

    // Nothing was sent: no queue rows, no ledger stamps.
    let queued: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM email_queue WHERE metadata->>'campaign_id' = $1")
            .bind(campaign.id.to_string())
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(queued, 0);
    let stamped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_campaign_recipients \
         WHERE campaign_id = $1 AND sent_at IS NOT NULL",
    )
    .bind(campaign.id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(stamped, 0);

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Unsubscribe exclusion on the sequence path
// ---------------------------------------------------------------------------

/// A recipient who clicks the dispatcher-generated unsubscribe link is
/// suppressed in BOTH stores and the next sequence send is refused. This is
/// the sequence-path successor of "unsubscribed recipient is excluded from
/// the next campaign dispatch".
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn unsubscribed_recipient_is_excluded_from_the_sequence_send() {
    let Some(fx) = fixture("sequence_unsub_excluded", fixture_options()).await else {
        return;
    };
    let step_execution_id = fx.seq.step_execution_id.expect("fixture enrolls");

    // The link the footer carries is a v2 opaque token; resolving it through
    // the persisted hash yields the canonical (tenant, lowercased email) pair.
    let link = fx
        .dispatcher
        .unsubscribe_link(&fx.tenant_id, Uuid::new_v4(), &fx.seq.email)
        .await
        .expect("v2 unsubscribe link persists its token hash");
    let token = link.rsplit('/').next().unwrap().to_string();
    assert!(
        !token.contains('.'),
        "v2 tokens are opaque, not v1 payloads"
    );
    let data = sales_autopilot::dispatcher::resolve_unsubscribe_token(&fx.db, &token)
        .await
        .expect("token lookup succeeds")
        .expect("dispatcher-generated link carries a valid token");
    assert_eq!(data.email, fx.seq.email.to_ascii_lowercase());
    assert_eq!(data.tenant_id, fx.tenant_id);

    ProductionCampaignDispatcher::suppress(
        &fx.db,
        &data.tenant_id,
        &data.email,
        "unsubscribe-link",
    )
    .await
    .unwrap();
    let sales_sup: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1 AND email = $2",
    )
    .bind(&fx.tenant_id)
    .bind(&data.email)
    .fetch_one(&fx.db)
    .await
    .unwrap();
    let platform_sup: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&fx.tenant_id)
            .bind(&data.email)
            .fetch_one(&fx.db)
            .await
            .unwrap();
    assert_eq!(sales_sup, 1, "sales-side suppression recorded");
    assert_eq!(platform_sup, 1, "platform suppression mirrored");

    let outcome = common::run_send_step(
        &fx.db,
        fx.dispatcher.clone(),
        &fx.tenant_id,
        step_execution_id,
    )
    .await;
    assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");
    let (state, skip_reason) = step_state(&fx.db, step_execution_id).await;
    assert_eq!(state, "skipped");
    assert!(
        skip_reason.as_deref().unwrap_or("").contains("suppressed"),
        "the unsubscribe must refuse the next send: {skip_reason:?}"
    );
    assert_eq!(message_count_for_step(&fx.db, step_execution_id).await, 0);
    assert_eq!(queue_count_for_step(&fx.db, step_execution_id).await, 0);

    common::cleanup_tenant(&fx.db, &fx.tenant_id).await;
}

// ---------------------------------------------------------------------------
// Unsubscribe endpoint: token flows (handler-level, through the router)
// ---------------------------------------------------------------------------

mod unsub_http {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use sales_autopilot::config::SalesConfig;
    use sales_autopilot::dispatcher::sign_unsubscribe_token_default_ttl;
    use sales_autopilot::routes::{self, AppState};
    use sales_autopilot::{
        calendar::CalendarService, crm::CrmBackend, enrichment::EnrichmentService,
        inbox::InboxManager,
    };

    fn build_app(db: &PgPool) -> axum::Router {
        let dispatch = common::test_dispatch_config();
        let dispatcher = Arc::new(
            ProductionCampaignDispatcher::new(
                dispatch.clone(),
                db.clone(),
                Arc::new(FakeAdmissionBackend::new()),
            )
            .unwrap(),
        );
        let state = AppState {
            campaigns: CampaignManager::new(50, db.clone()),
            dispatcher: Some(dispatcher),
            config: SalesConfig {
                dispatch,
                ..SalesConfig::default()
            },
            db: db.clone(),
            redis: deadpool_redis::Config::from_url("redis://127.0.0.1:16379")
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .unwrap(),
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            service_token: "test-key".into(),
            rate_limit_fallback: Arc::new(
                parking_lot::Mutex::new(std::collections::HashMap::new()),
            ),
            intelligence: Arc::new(sales_autopilot::intelligence::OfflineIntelligence::new()),
            strategist: Arc::new(sales_autopilot::personalization::MessageStrategist::new(
                db.clone(),
                sales_autopilot::knowledge::SalesKnowledgeBase::canonical(),
            )),
        };
        routes::router(state)
    }

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn get_unsubscribe_suppresses_and_renders_page() {
        let Some(db) = common::test_pool("unsub_get").await else {
            return;
        };
        let tenant_id = common::insert_test_tenant(&db, "unsub-get").await;
        let app = build_app(&db);

        let token = sign_unsubscribe_token_default_ttl(
            "integration-test-unsubscribe-secret-321",
            &tenant_id,
            "Opt.Out@Example.com",
        );
        // No auth headers: /u/* is public (HMAC is the authenticator).
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/u/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "branded page renders");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("Unsubscribed"), "branded page: {body}");

        // Both suppression stores contain the recipient (lowercased).
        let sales_sup: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1 AND email = 'opt.out@example.com'",
        )
        .bind(&tenant_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(sales_sup.0, 1);
        let platform_sup: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = 'opt.out@example.com'",
        )
        .bind(&tenant_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            platform_sup.0, 1,
            "mirror into the platform suppression table"
        );

        // DOUBLE unsubscribe: still 200, still exactly one row each.
        let resp2 = app
            .clone()
            .oneshot(
                Request::get(format!("/u/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::OK,
            "second unsubscribe is idempotent"
        );
        let sales_sup2: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1")
                .bind(&tenant_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(sales_sup2.0, 1, "no duplicate suppression row");

        common::cleanup_tenant(&db, &tenant_id).await;
    }

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn get_unsubscribe_redirects_when_configured() {
        let Some(db) = common::test_pool("unsub_redirect").await else {
            return;
        };
        let tenant_id = common::insert_test_tenant(&db, "unsub-redir").await;
        let mut dispatch = common::test_dispatch_config();
        dispatch.unsubscribe_redirect_url = Some("https://brand.example.com/goodbye".into());
        let dispatcher = Arc::new(
            ProductionCampaignDispatcher::new(
                dispatch.clone(),
                db.clone(),
                Arc::new(FakeAdmissionBackend::new()),
            )
            .unwrap(),
        );
        let state = AppState {
            campaigns: CampaignManager::new(50, db.clone()),
            dispatcher: Some(dispatcher),
            config: SalesConfig {
                dispatch,
                ..SalesConfig::default()
            },
            db: db.clone(),
            redis: deadpool_redis::Config::from_url("redis://127.0.0.1:16379")
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .unwrap(),
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            service_token: "test-key".into(),
            rate_limit_fallback: Arc::new(
                parking_lot::Mutex::new(std::collections::HashMap::new()),
            ),
            intelligence: Arc::new(sales_autopilot::intelligence::OfflineIntelligence::new()),
            strategist: Arc::new(sales_autopilot::personalization::MessageStrategist::new(
                db.clone(),
                sales_autopilot::knowledge::SalesKnowledgeBase::canonical(),
            )),
        };
        let app = routes::router(state);

        let token = sign_unsubscribe_token_default_ttl(
            "integration-test-unsubscribe-secret-321",
            &tenant_id,
            "redirect@example.com",
        );
        let resp = app
            .oneshot(
                Request::get(format!("/u/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "https://brand.example.com/goodbye"
        );

        common::cleanup_tenant(&db, &tenant_id).await;
    }

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn invalid_token_is_rejected() {
        let Some(db) = common::test_pool("unsub_invalid").await else {
            return;
        };
        let app = build_app(&db);

        // Tampered signature.
        let tenant_id = common::insert_test_tenant(&db, "unsub-bad").await;
        let mut token = sign_unsubscribe_token_default_ttl(
            "integration-test-unsubscribe-secret-321",
            &tenant_id,
            "tamper@example.com",
        );
        // Flip the last character of the signature.
        let last = token.len() - 1;
        token.replace_range(
            last..,
            if token.as_bytes()[last] == b'a' {
                "b"
            } else {
                "a"
            },
        );

        for method_and_body in [
            (axum::http::Method::GET, None),
            (
                axum::http::Method::POST,
                Some("List-Unsubscribe=One-Click".to_string()),
            ),
        ] {
            let (method, body) = method_and_body;
            let builder = Request::builder()
                .method(method.clone())
                .uri(format!("/u/{token}"));
            let request = match body {
                Some(b) => builder
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(b))
                    .unwrap(),
                None => builder.body(Body::empty()).unwrap(),
            };
            let resp = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{method} with tampered token must 400"
            );
        }

        // No suppression row leaked for the tampered token.
        let rows: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sales_unsubscribes WHERE email = 'tamper@example.com'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(rows.0, 0);

        common::cleanup_tenant(&db, &tenant_id).await;
    }

    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn rfc8058_post_requires_exact_body() {
        let Some(db) = common::test_pool("unsub_post_body").await else {
            return;
        };
        let tenant_id = common::insert_test_tenant(&db, "unsub-post").await;
        let app = build_app(&db);
        let token = sign_unsubscribe_token_default_ttl(
            "integration-test-unsubscribe-secret-321",
            &tenant_id,
            "post@example.com",
        );

        // Wrong body → 400 (and NOT suppressed).
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/u/{token}"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("unsubscribe=yes"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Correct body → 200 {"success":true} + suppression.
        let resp = app
            .oneshot(
                Request::post(format!("/u/{token}"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("List-Unsubscribe=One-Click"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("\"success\":true"));

        let sup: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sales_unsubscribes WHERE email = 'post@example.com'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(sup.0, 1);

        common::cleanup_tenant(&db, &tenant_id).await;
    }
}

// ---------------------------------------------------------------------------
// Inbox reply endpoint: compose + enqueue through email_queue (fix I-4)
// ---------------------------------------------------------------------------

mod reply_http {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use sales_autopilot::config::SalesConfig;
    use sales_autopilot::routes::{self, AppState};
    use sales_autopilot::{
        calendar::CalendarService, crm::CrmBackend, enrichment::EnrichmentService,
        inbox::InboxManager,
    };

    async fn reply_fixture(test_name: &str) -> Option<(axum::Router, PgPool, String, Uuid)> {
        let db = common::test_pool(test_name).await?;
        let tenant_id = common::insert_test_tenant(&db, test_name).await;
        let domain = common::unique_test_domain();
        common::insert_verified_domain(&db, &tenant_id, &domain).await;

        let dispatch = common::test_dispatch_config_for(&domain);
        let dispatcher = Arc::new(
            ProductionCampaignDispatcher::new(
                dispatch.clone(),
                db.clone(),
                Arc::new(FakeAdmissionBackend::new()),
            )
            .unwrap(),
        );
        let state = AppState {
            campaigns: CampaignManager::new(50, db.clone()),
            dispatcher: Some(dispatcher),
            config: SalesConfig {
                dispatch,
                ..SalesConfig::default()
            },
            db: db.clone(),
            redis: deadpool_redis::Config::from_url("redis://127.0.0.1:16379")
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .unwrap(),
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            service_token: "test-key".into(),
            rate_limit_fallback: Arc::new(
                parking_lot::Mutex::new(std::collections::HashMap::new()),
            ),
            intelligence: Arc::new(sales_autopilot::intelligence::OfflineIntelligence::new()),
            strategist: Arc::new(sales_autopilot::personalization::MessageStrategist::new(
                db.clone(),
                sales_autopilot::knowledge::SalesKnowledgeBase::canonical(),
            )),
        };

        // One inbound message from a lead.
        let inbox_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_inbox_messages (id, tenant_id, sender, subject, category, replied) \
             VALUES ($1, $2, 'prospect@example.com', 'Pricing question', 'lead', false)",
        )
        .bind(inbox_id)
        .bind(&tenant_id)
        .execute(&db)
        .await
        .unwrap();

        Some((routes::router(state), db, tenant_id, inbox_id))
    }

    fn reply_request(inbox_id: Uuid, tenant: &str, body: &str) -> Request<Body> {
        Request::post(format!("/inbox/{inbox_id}/reply"))
            .header("x-api-key", "test-key")
            .header("x-tenant-id", tenant)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({ "body": body })).unwrap(),
            ))
            .unwrap()
    }

    async fn reply_queue_rows(db: &PgPool, inbox_id: Uuid) -> Vec<(String, String, String)> {
        sqlx::query_as(
            "SELECT \"to\", subject, html FROM email_queue \
             WHERE metadata->>'inbox_message_id' = $1",
        )
        .bind(inbox_id.to_string())
        .fetch_all(db)
        .await
        .unwrap()
    }

    /// Happy path: the reply is composed, escaped and enqueued through the
    /// platform pipeline; the replied flag flips atomically.
    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn reply_composes_and_enqueues_through_email_queue() {
        let Some((app, db, tenant_id, inbox_id)) = reply_fixture("reply_happy").await else {
            return;
        };

        let resp = app
            .clone()
            .oneshot(reply_request(
                inbox_id,
                &tenant_id,
                "Thanks for reaching out!\n\n<script>alert('xss')</script> & regards",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["queued"], true);
        assert_eq!(body["replied"], true);
        assert_eq!(body["to"], "prospect@example.com");
        let message_id: Uuid = body["messageId"].as_str().unwrap().parse().unwrap();

        // One queue row: to = the correspondent, subject = Re: …
        let rows = reply_queue_rows(&db, inbox_id).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "prospect@example.com");
        assert_eq!(rows[0].1, "Re: Pricing question");
        // The hostile body text is HTML-ESCAPED in the composed part.
        assert!(
            rows[0]
                .2
                .contains("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt; &amp; regards"),
            "reply body must be HTML-escaped: {}",
            rows[0].2
        );
        assert!(!rows[0].2.contains("<script>"));
        // Plain-text part keeps the raw body.
        let text: (String,) =
            sqlx::query_as("SELECT text FROM email_queue WHERE metadata->>'inbox_message_id' = $1")
                .bind(inbox_id.to_string())
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(text.0.contains("<script>alert('xss')</script>"));

        // messages row with the deterministic reply idempotency key.
        let (key,): (String,) =
            sqlx::query_as("SELECT idempotency_key FROM messages WHERE id = $1")
                .bind(message_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(key, format!("sareply:{inbox_id}"));

        // replied flag stamped.
        let replied: (bool,) =
            sqlx::query_as("SELECT replied FROM sales_inbox_messages WHERE id = $1")
                .bind(inbox_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(replied.0);

        common::cleanup_tenant(&db, &tenant_id).await;
    }

    /// Double-click / retry: the second POST is an idempotent no-op —
    /// exactly one queue row, one messages row, no double send.
    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn reply_double_post_is_idempotent_no_double_send() {
        let Some((app, db, tenant_id, inbox_id)) = reply_fixture("reply_double").await else {
            return;
        };

        let first = app
            .clone()
            .oneshot(reply_request(inbox_id, &tenant_id, "first reply"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);

        let second = app
            .clone()
            .oneshot(reply_request(inbox_id, &tenant_id, "accidental second"))
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            StatusCode::ACCEPTED,
            "idempotent replay is a success, not an error"
        );
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(second.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            body["duplicate"], true,
            "response flags the duplicate: {body}"
        );
        assert_eq!(body["queued"], false);

        assert_eq!(reply_queue_rows(&db, inbox_id).await.len(), 1);
        let messages: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM messages WHERE idempotency_key = $1")
                .bind(format!("sareply:{inbox_id}"))
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(messages.0, 1, "still exactly one messages row");

        common::cleanup_tenant(&db, &tenant_id).await;
    }

    /// A correspondent who hard-bounced (platform suppressions) never gets
    /// the reply — and the message stays visibly unanswered.
    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn reply_to_suppressed_correspondent_refused() {
        let Some((app, db, tenant_id, inbox_id)) = reply_fixture("reply_suppressed").await else {
            return;
        };
        sqlx::query(
            "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at) \
             VALUES ($1, $2, 'prospect@example.com', 'hard_bounce', 'worker', NOW())",
        )
        .bind(apexmail_lib::id::generate_id("sup", 22))
        .bind(&tenant_id)
        .execute(&db)
        .await
        .unwrap();

        let resp = app
            .clone()
            .oneshot(reply_request(inbox_id, &tenant_id, "bouncing reply"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        assert_eq!(reply_queue_rows(&db, inbox_id).await.len(), 0);
        let replied: (bool,) =
            sqlx::query_as("SELECT replied FROM sales_inbox_messages WHERE id = $1")
                .bind(inbox_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(!replied.0, "failed reply must not flip the replied flag");

        common::cleanup_tenant(&db, &tenant_id).await;
    }

    /// Cross-tenant isolation: another tenant's reply to this message is a
    /// 404 and enqueues nothing.
    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn reply_cross_tenant_is_404() {
        let Some((app, db, tenant_id, inbox_id)) = reply_fixture("reply_cross_tenant").await else {
            return;
        };
        // NOTE: sales-autopilot's token model lets the caller address any
        // tenant (SALES_ALLOWED_TENANTS scopes this in production); the
        // handler itself must still scope the lookup to the caller tenant.
        let other_tenant = common::insert_test_tenant(&db, "reply-other").await;
        let resp = app
            .clone()
            .oneshot(reply_request(inbox_id, &other_tenant, "sneaky reply"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(reply_queue_rows(&db, inbox_id).await.len(), 0);

        common::cleanup_tenant(&db, &other_tenant).await;
        common::cleanup_tenant(&db, &tenant_id).await;
    }

    /// Unknown message id → 404, nothing enqueued.
    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn reply_to_missing_message_is_404() {
        let Some((app, db, tenant_id, _)) = reply_fixture("reply_missing").await else {
            return;
        };
        let resp = app
            .clone()
            .oneshot(reply_request(Uuid::new_v4(), &tenant_id, "hello?"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let queue: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM email_queue              WHERE metadata->>'kind' = 'inbox-reply' AND tenant_id = $1",
        )
        .bind(&tenant_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(queue.0, 0);

        common::cleanup_tenant(&db, &tenant_id).await;
    }

    /// Unverified sender domain: the pipeline gate refuses the reply
    /// (mirrors the REST send path's domain gate).
    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn reply_refused_when_sender_domain_not_ready() {
        let Some((app, db, tenant_id, inbox_id)) = reply_fixture("reply_no_domain").await else {
            return;
        };
        sqlx::query("DELETE FROM domains WHERE tenant_id = $1")
            .bind(&tenant_id)
            .execute(&db)
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(reply_request(inbox_id, &tenant_id, "cannot send this"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            body["error"].as_str().unwrap().contains("sender domain"),
            "error names the sender-domain problem: {body}"
        );
        assert_eq!(reply_queue_rows(&db, inbox_id).await.len(), 0);
        let replied: (bool,) =
            sqlx::query_as("SELECT replied FROM sales_inbox_messages WHERE id = $1")
                .bind(inbox_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(!replied.0);

        common::cleanup_tenant(&db, &tenant_id).await;
    }

    /// A campaign opt-out (sales_unsubscribes only) deliberately does NOT
    /// block a 1:1 reply — documented decision in enqueue_reply.
    #[tokio::test]
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    async fn campaign_optout_does_not_block_personal_reply() {
        let Some((app, db, tenant_id, inbox_id)) = reply_fixture("reply_campaign_optout").await
        else {
            return;
        };
        // The correspondent opted out of CAMPAIGNS (crate-local list only,
        // NOT the platform suppressions table).
        sqlx::query(
            "INSERT INTO sales_unsubscribes (tenant_id, email) VALUES ($1, 'prospect@example.com')",
        )
        .bind(&tenant_id)
        .execute(&db)
        .await
        .unwrap();

        let resp = app
            .clone()
            .oneshot(reply_request(
                inbox_id,
                &tenant_id,
                "still answering your question",
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "campaign opt-out must not block a 1:1 reply"
        );
        assert_eq!(reply_queue_rows(&db, inbox_id).await.len(), 1);

        common::cleanup_tenant(&db, &tenant_id).await;
    }
}
