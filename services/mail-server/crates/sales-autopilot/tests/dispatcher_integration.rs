//! Production dispatcher integration tests — aggressive, non-happy-path
//! heavy. Run against a real Postgres (soft-skip without one); see
//! `common/mod.rs` for the platform-schema bootstrap.

mod common;

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use sales_autopilot::campaigns::{CampaignEmailDispatcher, CampaignManager};
use sales_autopilot::dispatcher::{
    ProductionCampaignDispatcher, QuotaFuture, QuotaGateway, QuotaReservation,
};
use sales_autopilot::types::SalesError;

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/// Deterministic test double for the billing quota gateway.
///
/// Modes:
/// * new() — allow everything (limit = -1, billing's "unlimited"),
/// * `with_limit(n)` — allow exactly n reservations, then [`SalesError::QuotaExhausted`],
/// * `with_transient_failure_at(call)` — the given reserve call (1-based)
///   fails with a ServiceUnavailable, simulating a billing/DB hiccup.
///
/// NOTE: deliberately not `Default` — a derived Default would set limit=0
/// (deny everything); construct via [`FakeQuotaGateway::new`].
#[derive(Debug)]
struct FakeQuotaGateway {
    /// -1 = unlimited (billing convention).
    limit: AtomicI64,
    used: AtomicI64,
    transient_fail_at: AtomicI64,
    reserves: AtomicUsize,
    rollbacks: AtomicUsize,
}

impl FakeQuotaGateway {
    fn new() -> Self {
        Self {
            limit: AtomicI64::new(-1),
            used: AtomicI64::new(0),
            transient_fail_at: AtomicI64::new(0),
            reserves: AtomicUsize::new(0),
            rollbacks: AtomicUsize::new(0),
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
}

impl QuotaGateway for FakeQuotaGateway {
    fn reserve(&self, tenant_id: &str) -> QuotaFuture<'_, Result<QuotaReservation, SalesError>> {
        let tenant_id = tenant_id.to_string();
        let n = self.reserves.fetch_add(1, Ordering::SeqCst) as i64 + 1;
        Box::pin(async move {
            if self.transient_fail_at.load(Ordering::SeqCst) == n {
                return Err(SalesError::ServiceUnavailable(
                    "billing quota enforcement is temporarily unavailable".into(),
                ));
            }
            let used = self.used.fetch_add(1, Ordering::SeqCst) + 1;
            let limit = self.limit.load(Ordering::SeqCst);
            if limit >= 0 && used > limit {
                // Mirror the Lua semantics: denial does not consume quota.
                self.used.fetch_sub(1, Ordering::SeqCst);
                return Err(SalesError::QuotaExhausted(tenant_id));
            }
            Ok(QuotaReservation {
                event_id: Uuid::new_v4(),
                recorded_at: chrono::Utc::now(),
            })
        })
    }

    fn rollback(
        &self,
        _tenant_id: &str,
        _reservation: &QuotaReservation,
    ) -> QuotaFuture<'_, Result<(), SalesError>> {
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    db: PgPool,
    tenant_id: String,
    /// The per-fixture verified sender domain (globally unique in canonical
    /// `domains`); rebuilt dispatchers must keep sending from it.
    domain: String,
    manager: CampaignManager,
    dispatcher: Arc<ProductionCampaignDispatcher>,
    quota: Arc<FakeQuotaGateway>,
}

async fn fixture(test_name: &str) -> Option<Fixture> {
    let db = common::test_pool(test_name).await?;
    let tenant_id = common::insert_test_tenant(&db, test_name).await;
    // Per-fixture domain: canonical domains.name is GLOBALLY unique and this
    // suite's tests share one database, so each fixture claims its own.
    let domain = common::unique_test_domain();
    common::insert_verified_domain(&db, &tenant_id, &domain).await;

    let quota = Arc::new(FakeQuotaGateway::new());
    let dispatcher = Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(&domain),
            db.clone(),
            quota.clone() as Arc<dyn QuotaGateway>,
        )
        .expect("test dispatch config must be valid"),
    );
    let manager = CampaignManager::new(50, db.clone()).with_email_dispatcher(
        dispatcher.clone() as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>
    );
    Some(Fixture {
        db,
        tenant_id,
        domain,
        manager,
        dispatcher,
        quota,
    })
}

async fn make_campaign(
    fx: &Fixture,
    template_subject: &str,
    template_html: &str,
    recipients: &[&str],
) -> Uuid {
    let template_id = common::insert_template(
        &fx.db,
        &fx.tenant_id,
        template_subject,
        template_html,
        Some("Hello {{name}}, plain text."),
    )
    .await;
    let campaign = fx
        .manager
        .create_campaign(
            fx.tenant_id.clone(),
            "Integration wave".into(),
            template_id,
            String::new(),
        )
        .await
        .unwrap();
    fx.manager
        .add_recipients(
            &fx.tenant_id,
            campaign.id,
            recipients.iter().map(|s| s.to_string()).collect(),
        )
        .await
        .unwrap();
    campaign.id
}

async fn queue_rows_for_campaign(
    db: &PgPool,
    campaign_id: Uuid,
) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        r#"SELECT "to", status, headers->>'List-Unsubscribe' FROM email_queue
           WHERE metadata->>'campaign_id' = $1 ORDER BY "to""#,
    )
    .bind(campaign_id.to_string())
    .fetch_all(db)
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------
// Happy path: real enqueue through the platform pipeline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dispatcher_enqueues_into_platform_pipeline() {
    let Some(fx) = fixture("dispatch_enqueues").await else {
        return;
    };
    let campaign_id = make_campaign(
        &fx,
        "Hi {{first_name}} from {{company}}",
        "<html><body><p>Hello {{first_name}}, meet {{company}}!</p><a href=\"https://example.com/x\">x</a></body></html>",
        &["alice@example.com", "bob@example.com"],
    )
    .await;

    // CRM lead profile for alice with hostile personalization data.
    // (`domain` is NOT NULL in the platform sales_leads schema.)
    sqlx::query(
        "INSERT INTO sales_leads (id, tenant_id, domain, contact_email, contact_name, company_name, title) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind("lead-alice")
    .bind(&fx.tenant_id)
    .bind("example.com")
    .bind("alice@example.com")
    .bind("<script>alert('xss')</script>")
    .bind("ACME & Sons")
    .bind("CTO")
    .execute(&fx.db)
    .await
    .unwrap();

    fx.manager
        .start_campaign(&fx.tenant_id, campaign_id)
        .await
        .unwrap();

    // `messages` audit rows exist with campaign idempotency keys.
    let message_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT idempotency_key, status FROM messages \
         WHERE tenant_id = $1 AND idempotency_key LIKE $2 ORDER BY idempotency_key",
    )
    .bind(&fx.tenant_id)
    .bind(format!("sacmp:{campaign_id}:%"))
    .fetch_all(&fx.db)
    .await
    .unwrap();
    assert_eq!(message_rows.len(), 2, "one messages row per recipient");
    assert!(message_rows
        .iter()
        .all(|(k, _)| k.starts_with(&format!("sacmp:{campaign_id}:"))));
    assert!(message_rows.iter().all(|(_, s)| s == "queued"));

    // `email_queue` rows: pending, single-recipient, List-Unsubscribe header.
    let queue = queue_rows_for_campaign(&fx.db, campaign_id).await;
    assert_eq!(queue.len(), 2);
    for (to, status, list_unsub) in &queue {
        assert_eq!(status, "pending", "queue row for {to} must start pending");
        let link = list_unsub
            .as_ref()
            .expect("List-Unsubscribe header present");
        assert!(
            link.starts_with('<') && link.ends_with('>'),
            "RFC 2369 angle form: {link}"
        );
        assert!(
            link.contains("/u/"),
            "link points at the unsubscribe endpoint: {link}"
        );
    }

    // List-Unsubscribe-Post one-click header.
    let post_headers: Vec<(String,)> = sqlx::query_as(
        "SELECT headers->>'List-Unsubscribe-Post' FROM email_queue \
         WHERE metadata->>'campaign_id' = $1",
    )
    .bind(campaign_id.to_string())
    .fetch_all(&fx.db)
    .await
    .unwrap();
    assert!(post_headers
        .iter()
        .all(|(v,)| v == "List-Unsubscribe=One-Click"));

    // Personalization: alice's lead name is HTML-ESCAPED in subject + html.
    let alice_html: (String,) = sqlx::query_as(
        "SELECT html FROM email_queue WHERE metadata->>'campaign_id' = $1 AND \"to\" = 'alice@example.com'",
    )
    .bind(campaign_id.to_string())
    .fetch_one(&fx.db)
    .await
    .unwrap();
    assert!(
        alice_html
            .0
            .contains("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"),
        "lead name must be HTML-escaped: {}",
        alice_html.0
    );
    assert!(
        !alice_html.0.contains("<script>alert"),
        "raw script must never appear"
    );
    assert!(
        alice_html.0.contains("ACME &amp; Sons"),
        "company ampersand escaped"
    );
    // CAN-SPAM footer with working unsubscribe link.
    assert!(alice_html.0.contains("Unsubscribe</a>"));

    let alice_subject: (String,) = sqlx::query_as(
        "SELECT subject FROM email_queue WHERE metadata->>'campaign_id' = $1 AND \"to\" = 'alice@example.com'",
    )
    .bind(campaign_id.to_string())
    .fetch_one(&fx.db)
    .await
    .unwrap();
    assert!(
        alice_subject.0.contains("&lt;script&gt;"),
        "subject is escaped too: {}",
        alice_subject.0
    );

    // Send ledger stamped + linked to the messages rows; campaign counter advanced.
    let ledger: Vec<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT email, message_id FROM sales_campaign_recipients \
         WHERE campaign_id = $1 ORDER BY email",
    )
    .bind(campaign_id)
    .fetch_all(&fx.db)
    .await
    .unwrap();
    assert_eq!(ledger.len(), 2);
    assert!(
        ledger.iter().all(|(_, m)| m.is_some()),
        "message_id recorded per recipient"
    );

    let sent: (i64,) = sqlx::query_as("SELECT sent FROM sales_campaigns WHERE id = $1")
        .bind(campaign_id)
        .fetch_one(&fx.db)
        .await
        .unwrap();
    assert_eq!(
        sent.0, 2,
        "campaign sent counter advanced inside the enqueue tx"
    );
}

// ---------------------------------------------------------------------------
// Non-happy-path: suppression (platform table), the way messages.rs reads it
// ---------------------------------------------------------------------------

#[tokio::test]
async fn platform_suppressions_exclude_recipients() {
    let Some(fx) = fixture("platform_suppressions").await else {
        return;
    };
    let campaign_id = make_campaign(
        &fx,
        "s",
        "<p>x</p>",
        &["keep@example.com", "bounced@example.com"],
    )
    .await;

    // Hard bounce recorded by the platform worker into `suppressions`
    // (NOT the crate-local sales_unsubscribes — that path is covered by
    // can_spam.rs; this proves the poll of the PLATFORM table works).
    sqlx::query(
        "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at) \
         VALUES ($1, $2, $3, 'hard_bounce', 'worker', NOW())",
    )
    .bind(apexmail_lib::id::generate_id("sup", 22))
    .bind(&fx.tenant_id)
    .bind("bounced@example.com")
    .execute(&fx.db)
    .await
    .unwrap();

    fx.manager
        .start_campaign(&fx.tenant_id, campaign_id)
        .await
        .unwrap();

    let queue = queue_rows_for_campaign(&fx.db, campaign_id).await;
    assert_eq!(queue.len(), 1, "suppressed recipient excluded: {queue:?}");
    assert_eq!(queue[0].0, "keep@example.com");
}

// ---------------------------------------------------------------------------
// Non-happy-path: crash-restart idempotency (never double-send)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn crash_restart_does_not_double_send() {
    let Some(fx) = fixture("crash_restart").await else {
        return;
    };
    let campaign_id = make_campaign(&fx, "s", "<p>x</p>", &["victim@example.com"]).await;

    // First dispatch succeeds.
    fx.manager
        .start_campaign(&fx.tenant_id, campaign_id)
        .await
        .unwrap();
    assert_eq!(queue_rows_for_campaign(&fx.db, campaign_id).await.len(), 1);

    // Simulate a crash between the ledger write and enqueue of an OLDER
    // code path: the messages row survived with the idempotency key, but the
    // ledger stamp was lost (sent_at reset).
    sqlx::query(
        "UPDATE sales_campaign_recipients SET sent_at = NULL, message_id = NULL \
         WHERE campaign_id = $1 AND email = 'victim@example.com'",
    )
    .bind(campaign_id)
    .execute(&fx.db)
    .await
    .unwrap();

    // "Restart": the scheduler picks the recipient up again and dispatches.
    let enqueued = fx
        .dispatcher
        .dispatch_batch(
            &fx.tenant_id,
            campaign_id,
            &fetch_template_id(&fx, campaign_id).await,
            &fx.manager
                .due_recipients(&fx.tenant_id, campaign_id, 100)
                .await
                .unwrap(),
        )
        .await
        .unwrap();

    // The idempotency key must prevent the double-send: nothing NEW enqueued.
    assert_eq!(enqueued, 0, "duplicate must not enqueue a second time");
    // The duplicate path still RESERVED quota (before the conflict was
    // detected) and released it afterwards — no quota leak.
    assert!(
        fx.quota.rollbacks() >= 1,
        "duplicate path must release its reservation"
    );
    assert_eq!(
        queue_rows_for_campaign(&fx.db, campaign_id).await.len(),
        1,
        "still exactly one queue row"
    );
    let messages: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM messages WHERE idempotency_key LIKE $1")
            .bind(format!("sacmp:{campaign_id}:%"))
            .fetch_one(&fx.db)
            .await
            .unwrap();
    assert_eq!(messages.0, 1, "still exactly one messages row");

    // And the ledger is stamped again, so no infinite retry.
    let unstamped: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sales_campaign_recipients WHERE campaign_id = $1 AND sent_at IS NULL",
    )
    .bind(campaign_id)
    .fetch_one(&fx.db)
    .await
    .unwrap();
    assert_eq!(unstamped.0, 0);

    // The sent counter was NOT double-incremented.
    let sent: (i64,) = sqlx::query_as("SELECT sent FROM sales_campaigns WHERE id = $1")
        .bind(campaign_id)
        .fetch_one(&fx.db)
        .await
        .unwrap();
    assert_eq!(sent.0, 1);
}

async fn fetch_template_id(fx: &Fixture, campaign_id: Uuid) -> String {
    let (template_id,): (String,) =
        sqlx::query_as("SELECT template_id FROM sales_campaigns WHERE id = $1")
            .bind(campaign_id)
            .fetch_one(&fx.db)
            .await
            .unwrap();
    template_id
}

// ---------------------------------------------------------------------------
// Non-happy-path: quota exhausted → campaign PAUSES WITH ERROR STATE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quota_exhausted_pauses_campaign_with_error_state() {
    let Some(mut fx) = fixture("quota_exhausted").await else {
        return;
    };
    fx.quota = Arc::new(FakeQuotaGateway::with_limit(1));
    fx.dispatcher = Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(&fx.domain),
            fx.db.clone(),
            fx.quota.clone() as Arc<dyn QuotaGateway>,
        )
        .unwrap(),
    );
    fx.manager =
        CampaignManager::new(50, fx.db.clone())
            .with_email_dispatcher(fx.dispatcher.clone()
                as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>);

    let campaign_id = make_campaign(
        &fx,
        "s",
        "<p>x</p>",
        &["a@example.com", "b@example.com", "c@example.com"],
    )
    .await;

    let err = fx
        .manager
        .start_campaign(&fx.tenant_id, campaign_id)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("quota"),
        "error must name the quota exhaustion: {err}"
    );

    let (status, last_error, sent): (String, Option<String>, i64) =
        sqlx::query_as("SELECT status, last_error, sent FROM sales_campaigns WHERE id = $1")
            .bind(campaign_id)
            .fetch_one(&fx.db)
            .await
            .unwrap();
    assert_eq!(status, "paused", "campaign must pause, not stay active");
    assert!(
        last_error.as_deref().unwrap_or("").contains("quota"),
        "error state recorded: {last_error:?}"
    );
    assert_eq!(sent, 1, "the one pre-exhaustion recipient was sent");

    // Exactly one queue row — no partial-silent overflow.
    assert_eq!(queue_rows_for_campaign(&fx.db, campaign_id).await.len(), 1);
    // The exhausted reserve attempts were called for every recipient tried,
    // and denial did not leak a reservation (rollback never fires for
    // exhaustion — the Lua check-and-incr does not consume on denial).
    assert!(fx.quota.reserves() >= 2, "denied reserves were attempted");

    // Quota resets: restarting the campaign continues the remaining recipients.
    fx.quota = Arc::new(FakeQuotaGateway::new());
    fx.dispatcher = Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(&fx.domain),
            fx.db.clone(),
            fx.quota.clone() as Arc<dyn QuotaGateway>,
        )
        .unwrap(),
    );
    fx.manager =
        CampaignManager::new(50, fx.db.clone())
            .with_email_dispatcher(fx.dispatcher.clone()
                as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>);
    fx.manager
        .start_campaign(&fx.tenant_id, campaign_id)
        .await
        .unwrap();
    assert_eq!(
        queue_rows_for_campaign(&fx.db, campaign_id).await.len(),
        3,
        "resume sends only the remaining recipients"
    );
}

// ---------------------------------------------------------------------------
// Non-happy-path: transient batch failure → retried, idempotently
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_failure_is_retried_without_duplicates() {
    let Some(mut fx) = fixture("batch_retry").await else {
        return;
    };
    // The SECOND reserve call fails with a transient error: recipient 1 is
    // enqueued, then the batch aborts.
    fx.quota = Arc::new(FakeQuotaGateway::with_transient_failure_at(2));
    fx.dispatcher = Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(&fx.domain),
            fx.db.clone(),
            fx.quota.clone() as Arc<dyn QuotaGateway>,
        )
        .unwrap(),
    );
    fx.manager =
        CampaignManager::new(50, fx.db.clone())
            .with_email_dispatcher(fx.dispatcher.clone()
                as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>);

    let campaign_id =
        make_campaign(&fx, "s", "<p>x</p>", &["a@example.com", "b@example.com"]).await;

    let err = fx
        .manager
        .start_campaign(&fx.tenant_id, campaign_id)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SalesError::ServiceUnavailable(_)),
        "transient failure surfaces, got {err:?}"
    );

    // The batch failed mid-way but the campaign stays ACTIVE (retryable).
    let (status,): (String,) = sqlx::query_as("SELECT status FROM sales_campaigns WHERE id = $1")
        .bind(campaign_id)
        .fetch_one(&fx.db)
        .await
        .unwrap();
    assert_eq!(status, "active");
    // The failed reserve attempt did not leak a reservation (rollback is
    // not needed for a failed reserve — no quota was ever granted).

    // Health restored: the scheduler tick retries the batch idempotently.
    fx.quota = Arc::new(FakeQuotaGateway::new());
    fx.dispatcher = Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(&fx.domain),
            fx.db.clone(),
            fx.quota.clone() as Arc<dyn QuotaGateway>,
        )
        .unwrap(),
    );
    fx.manager =
        CampaignManager::new(50, fx.db.clone())
            .with_email_dispatcher(fx.dispatcher.clone()
                as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>);

    let template_id = fetch_template_id(&fx, campaign_id).await;
    let enqueued = sales_autopilot::scheduler::process_campaign(
        &fx.manager,
        &fx.dispatcher,
        100,
        campaign_id,
        &fx.tenant_id,
        &template_id,
    )
    .await
    .unwrap();

    assert_eq!(enqueued, 1, "only the unsent recipient is dispatched");
    let queue = queue_rows_for_campaign(&fx.db, campaign_id).await;
    assert_eq!(queue.len(), 2, "no duplicates after retry: {queue:?}");

    // No due recipients remain ⇒ the tick completes the campaign.
    sales_autopilot::scheduler::process_campaign(
        &fx.manager,
        &fx.dispatcher,
        100,
        campaign_id,
        &fx.tenant_id,
        &template_id,
    )
    .await
    .unwrap();
    let (status,): (String,) = sqlx::query_as("SELECT status FROM sales_campaigns WHERE id = $1")
        .bind(campaign_id)
        .fetch_one(&fx.db)
        .await
        .unwrap();
    assert_eq!(status, "completed");
}

// ---------------------------------------------------------------------------
// Non-happy-path: unverified sender domain refuses the whole campaign
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unverified_sender_domain_refuses_dispatch() {
    let Some(fx) = fixture("unverified_domain").await else {
        return;
    };
    // Tenant has NO verified domain for the sender's domain.
    sqlx::query("DELETE FROM domains WHERE tenant_id = $1")
        .bind(&fx.tenant_id)
        .execute(&fx.db)
        .await
        .unwrap();

    let campaign_id = make_campaign(&fx, "s", "<p>x</p>", &["a@example.com"]).await;
    let err = fx
        .manager
        .start_campaign(&fx.tenant_id, campaign_id)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("not verified"),
        "error must name the sender-domain problem: {err}"
    );
    assert_eq!(queue_rows_for_campaign(&fx.db, campaign_id).await.len(), 0);
}

// ---------------------------------------------------------------------------
// Missing template refuses dispatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_template_refuses_dispatch() {
    let Some(fx) = fixture("missing_template").await else {
        return;
    };
    let campaign = fx
        .manager
        .create_campaign(
            fx.tenant_id.clone(),
            "Broken".into(),
            "tpl_does_not_exist".into(),
            String::new(),
        )
        .await
        .unwrap();
    fx.manager
        .add_recipients(&fx.tenant_id, campaign.id, vec!["a@example.com".into()])
        .await
        .unwrap();

    let err = fx
        .manager
        .start_campaign(&fx.tenant_id, campaign.id)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("template"),
        "error must name the missing template: {err}"
    );
    assert_eq!(queue_rows_for_campaign(&fx.db, campaign.id).await.len(), 0);
}

// ---------------------------------------------------------------------------
// Stats reconciliation: opens/clicks flow back into campaign columns
// ---------------------------------------------------------------------------

#[tokio::test]
async fn campaign_stats_reconcile_from_platform_tracking() {
    let Some(fx) = fixture("stats_reconcile").await else {
        return;
    };
    let campaign_id = make_campaign(
        &fx,
        "s",
        "<p>track me</p>",
        &["a@example.com", "b@example.com"],
    )
    .await;
    fx.manager
        .start_campaign(&fx.tenant_id, campaign_id)
        .await
        .unwrap();

    // Simulate the tracking service recording an open + a click for
    // recipient a's message.
    sqlx::query(
        "UPDATE messages SET open_count = 1, click_count = 1 \
         WHERE idempotency_key = $1",
    )
    .bind(format!("sacmp:{campaign_id}:a@example.com"))
    .execute(&fx.db)
    .await
    .unwrap();

    fx.manager
        .reconcile_campaign_stats(campaign_id)
        .await
        .unwrap();

    let (opened, clicked, sent): (i64, i64, i64) =
        sqlx::query_as("SELECT opened, clicked, sent FROM sales_campaigns WHERE id = $1")
            .bind(campaign_id)
            .fetch_one(&fx.db)
            .await
            .unwrap();
    assert_eq!(sent, 2);
    assert_eq!(opened, 1, "one recipient opened");
    assert_eq!(clicked, 1, "one recipient clicked");
}

// ---------------------------------------------------------------------------
// Dry-run: renders + validates WITHOUT enqueueing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dry_run_renders_without_enqueueing() {
    let Some(fx) = fixture("dry_run").await else {
        return;
    };
    let campaign_id = make_campaign(
        &fx,
        "Hi {{first_name}}",
        "<html><body><p>Hello {{first_name}}</p></body></html>",
        &["alice@example.com", "bob@example.com", "gone@example.com"],
    )
    .await;
    fx.manager
        .suppress_recipient(&fx.tenant_id, "gone@example.com")
        .await
        .unwrap();

    let report = fx
        .manager
        .dry_run(&fx.tenant_id, campaign_id, 5, Some(fx.dispatcher.as_ref()))
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
    assert_eq!(queue_rows_for_campaign(&fx.db, campaign_id).await.len(), 0);
    let stamped: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sales_campaign_recipients WHERE campaign_id = $1 AND sent_at IS NOT NULL",
    )
    .bind(campaign_id)
    .fetch_one(&fx.db)
    .await
    .unwrap();
    assert_eq!(stamped.0, 0);
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
                Arc::new(FakeQuotaGateway::new()),
            )
            .unwrap(),
        );
        let state = AppState {
            campaigns: CampaignManager::new(50, db.clone())
                .with_email_dispatcher(dispatcher.clone()
                    as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>),
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
        };
        routes::router(state)
    }

    #[tokio::test]
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
    }

    #[tokio::test]
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
                Arc::new(FakeQuotaGateway::new()),
            )
            .unwrap(),
        );
        let state = AppState {
            campaigns: CampaignManager::new(50, db.clone())
                .with_email_dispatcher(dispatcher.clone()
                    as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>),
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
    }

    #[tokio::test]
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
    }

    #[tokio::test]
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
    }

    #[tokio::test]
    async fn unsubscribed_recipient_is_excluded_from_next_dispatch() {
        let Some(db) = common::test_pool("unsub_excluded").await else {
            return;
        };
        let tenant_id = common::insert_test_tenant(&db, "unsub-excl").await;
        let domain = common::unique_test_domain();
        common::insert_verified_domain(&db, &tenant_id, &domain).await;

        let quota = Arc::new(FakeQuotaGateway::new());
        let dispatcher = Arc::new(
            ProductionCampaignDispatcher::new(
                common::test_dispatch_config_for(&domain),
                db.clone(),
                quota.clone() as Arc<dyn QuotaGateway>,
            )
            .unwrap(),
        );
        let manager =
            CampaignManager::new(50, db.clone())
                .with_email_dispatcher(dispatcher.clone()
                    as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>);

        let template_id =
            common::insert_template(&db, &tenant_id, "s", "<p>x</p>", Some("t")).await;
        let campaign = manager
            .create_campaign(tenant_id.clone(), "wave".into(), template_id, String::new())
            .await
            .unwrap();
        manager
            .add_recipients(
                &tenant_id,
                campaign.id,
                vec!["stay@example.com".into(), "leave@example.com".into()],
            )
            .await
            .unwrap();

        // "leave" clicks the unsubscribe link generated by the dispatcher.
        let link = dispatcher.unsubscribe_link(&tenant_id, campaign.id, "leave@example.com");
        let token = link.rsplit('/').next().unwrap().to_string();
        let data = sales_autopilot::dispatcher::verify_unsubscribe_token(
            "integration-test-unsubscribe-secret-321",
            &token,
        )
        .expect("dispatcher-generated link carries a valid token");
        assert_eq!(data.email, "leave@example.com");
        ProductionCampaignDispatcher::suppress(
            &db,
            &data.tenant_id,
            &data.email,
            "unsubscribe-link",
        )
        .await
        .unwrap();

        manager
            .start_campaign(&tenant_id, campaign.id)
            .await
            .unwrap();
        let queue: Vec<(String,)> =
            sqlx::query_as("SELECT \"to\" FROM email_queue WHERE metadata->>'campaign_id' = $1")
                .bind(campaign.id.to_string())
                .fetch_all(&db)
                .await
                .unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(
            queue[0].0, "stay@example.com",
            "unsubscribed recipient excluded"
        );
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
                Arc::new(FakeQuotaGateway::new()),
            )
            .unwrap(),
        );
        let state = AppState {
            campaigns: CampaignManager::new(50, db.clone())
                .with_email_dispatcher(dispatcher.clone()
                    as Arc<dyn sales_autopilot::campaigns::CampaignEmailDispatcher>),
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
    }

    /// Double-click / retry: the second POST is an idempotent no-op —
    /// exactly one queue row, one messages row, no double send.
    #[tokio::test]
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
    }

    /// A correspondent who hard-bounced (platform suppressions) never gets
    /// the reply — and the message stays visibly unanswered.
    #[tokio::test]
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
    }

    /// Cross-tenant isolation: another tenant's reply to this message is a
    /// 404 and enqueues nothing.
    #[tokio::test]
    async fn reply_cross_tenant_is_404() {
        let Some((app, db, _tenant_id, inbox_id)) = reply_fixture("reply_cross_tenant").await
        else {
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
    }

    /// Unknown message id → 404, nothing enqueued.
    #[tokio::test]
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
    }

    /// Unverified sender domain: the pipeline gate refuses the reply
    /// (mirrors the REST send path's domain gate).
    #[tokio::test]
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
    }

    /// A campaign opt-out (sales_unsubscribes only) deliberately does NOT
    /// block a 1:1 reply — documented decision in enqueue_reply.
    #[tokio::test]
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
    }
}
