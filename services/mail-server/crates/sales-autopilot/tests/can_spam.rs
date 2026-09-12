//! CAN-SPAM regression tests on the surviving sequence send path.
//!
//! These tests used to run through the deleted second campaign send engine
//! (`CampaignEmailDispatcher` / `CampaignManager::start_campaign` dispatch).
//! The one-send-engine refactor removed that engine; the subject matter is
//! re-expressed against the surviving path, which is:
//!
//! `sales_actions` (leased, fenced) → `SequenceStepHandler` →
//! `decision_engine::decide` → `ProductionCampaignDispatcher::enqueue_sequenced`
//! → `messages` + `email_queue`.
//!
//! * the opt-out footer — unsubscribe link in HTML **and** text, plus the
//!   truthful business-contact disclosure (the footer must never claim a
//!   signup that did not happen) — is pure renderer coverage and runs by
//!   default;
//! * a suppressed recipient is refused at enrollment and again at the
//!   pre-send recheck (live, `#[ignore]`d);
//! * over-mailing is blocked by the surviving frequency control: the
//!   per-account weekly budget enforced inside `decision_engine::decide`. The
//!   per-recipient 7-day cap survives only in the read-only legacy `dry_run`
//!   funnel (covered by `dispatcher_integration.rs::dry_run_renders_without_enqueueing`);
//! * a deployment with no sales sender identity fails loudly instead of
//!   pretending to send (live, `#[ignore]`d).
//!
//! `mod common` provisions the canonical platform schema through the real
//! production migrator plus the sales schema via `routes::initialize_schema`.

mod common;

use std::sync::Arc;

use sales_autopilot::actions::ActionOutcome;
use sales_autopilot::campaigns::DispatchRecipient;
use sales_autopilot::dispatcher::{
    render_for_recipient, render_for_recipient_with_footer, render_outreach_footer, FooterReason,
    OutreachFooter, ProductionCampaignDispatcher, TemplateContent,
};
use sales_autopilot::enrollments::{self, StartOutreachRequest};

// ---------------------------------------------------------------------------
// Pure footer / disclosure tests (no database; run by default)
// ---------------------------------------------------------------------------

fn template() -> TemplateContent {
    TemplateContent {
        subject: "Hi {{first_name}}".into(),
        html_body: Some("<html><body><p>Hello {{first_name}}</p></body></html>".into()),
        text_body: Some("Hello {{first_name}}, plain text.".into()),
    }
}

fn recipient(link: &str) -> DispatchRecipient {
    DispatchRecipient::new("prospect@corp.example", link)
}

fn business_footer<'a>(link: &'a str) -> OutreachFooter<'a> {
    OutreachFooter {
        sender_identity: "ApexMail Sales",
        reason: FooterReason::BusinessContact {
            basis: "your organisation appears to be a potential fit for ApexMail's email delivery platform.",
        },
        unsubscribe_link: link,
        postal_address: Some("1 Example Street, Tallinn"),
        privacy_url: Some("https://apexmail.example/privacy"),
    }
}

/// The opt-out link must reach the recipient in BOTH the HTML and the text
/// part; the old campaign dispatcher attached this footer per dispatch, the
/// renderer is the same implementation on the sequence path.
#[test]
fn footer_carries_the_opt_out_link_in_html_and_text() {
    let link = "https://sales.apexmail.ee/u/signed-token-abc";
    let rendered =
        render_for_recipient_with_footer(&template(), &recipient(link), business_footer(link))
            .expect("template renders");
    let html = rendered.html.expect("html part");
    let text = rendered.text.expect("text part");

    assert!(
        html.contains(&format!("href=\"{link}\"")),
        "HTML footer must link the unsubscribe endpoint: {html}"
    );
    assert!(
        html.contains("Unsubscribe</a>"),
        "unsubscribe anchor: {html}"
    );
    assert!(
        html.find("Unsubscribe</a>").unwrap() < html.find("</body>").unwrap(),
        "the footer must be inserted inside the body"
    );
    // Compliance disclosure rides along with the link.
    assert!(html.contains("1 Example Street, Tallinn"), "{html}");
    assert!(html.contains("Privacy"), "{html}");

    assert!(
        text.contains(&format!("Unsubscribe: {link}")),
        "plain-text footer must carry the same opt-out link: {text}"
    );
    assert!(text.contains("1 Example Street, Tallinn"), "{text}");

    // The footer builder itself, independent of a template.
    let (footer_html, footer_text) = render_outreach_footer(&business_footer(link));
    assert!(footer_html.contains(link));
    assert!(footer_text.contains(link));
}

/// The footer may never manufacture consent: a cold business contact must get
/// the business-contact disclaimer, not a signup/opt-in claim.
#[test]
fn footer_never_claims_a_signup_that_did_not_happen() {
    let link = "https://sales.apexmail.ee/u/token";
    let (html, text) = render_outreach_footer(&business_footer(link));

    for body in [&html, &text] {
        assert!(
            body.contains("business contact"),
            "disclaimer missing: {body}"
        );
        assert!(
            body.contains("not claiming that you signed up"),
            "the no-signup disclaimer is the point of the fix: {body}"
        );
        assert!(
            !body.contains("signed up at ApexMail"),
            "the old false consent claim must be gone: {body}"
        );
        assert!(
            !body.contains("opted in to ApexMail communications"),
            "a business contact did not opt in: {body}"
        );
    }

    // The default render path must be truthful too: it carries the
    // business-contact footer, never a fabricated consent claim.
    let rendered = render_for_recipient(&template(), &recipient(link), "ApexMail Sales")
        .expect("template renders");
    let html = rendered.html.expect("html part");
    assert!(html.contains("business contact"), "{html}");
    assert!(
        !html.contains("opted in to ApexMail communications"),
        "{html}"
    );
}

/// Hostile footer inputs are HTML-escaped before interpolation.
#[test]
fn footer_escapes_sender_identity_and_basis() {
    let footer = OutreachFooter {
        sender_identity: "<script>alert('identity')</script>",
        reason: FooterReason::BusinessContact {
            basis: "<b>hostile basis</b>",
        },
        unsubscribe_link: "https://x.example/u/a?b=1&c=2",
        postal_address: None,
        privacy_url: None,
    };
    let (html, _) = render_outreach_footer(&footer);
    assert!(
        !html.contains("<script>"),
        "raw script must never appear: {html}"
    );
    assert!(html.contains("&lt;script&gt;"), "{html}");
    assert!(html.contains("&lt;b&gt;hostile basis&lt;/b&gt;"), "{html}");
    assert!(
        html.contains("?b=1&amp;c=2"),
        "link ampersand escaped: {html}"
    );
}

// ---------------------------------------------------------------------------
// Live tests (canonical test database; ignored by default)
// ---------------------------------------------------------------------------

fn dispatcher_for(db: &sqlx::PgPool, domain: &str) -> Arc<ProductionCampaignDispatcher> {
    Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(domain),
            db.clone(),
            Arc::new(common::AllowAllQuotaGateway),
        )
        .expect("test dispatch config must be valid"),
    )
}

/// Opted-out recipients must never be mailed — neither when the suppression
/// predates enrollment (the canonical enrollment gate rejects the contact) nor
/// when it lands after the step was queued (the pre-send Decision Packet
/// refuses the send). The old test asserted the dispatch batch skipped them;
/// the subject is unchanged, the mechanism is the canonical one.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn opted_out_recipient_is_refused_at_enrollment_and_at_send_time() {
    let Some(db) = common::test_pool("can_spam_optout").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "can-spam-optout").await;

    // ── Part A: suppression recorded BEFORE enrollment ──────────────────
    let pending = common::seed_sequence_fixture(
        &db,
        &tenant,
        common::SequenceFixtureOptions::default().without_enrollment(),
    )
    .await;
    sqlx::query(
        "INSERT INTO sales_unsubscribes (tenant_id, email) VALUES ($1, lower($2)) \
         ON CONFLICT (tenant_id, email) DO NOTHING",
    )
    .bind(&tenant)
    .bind(&pending.email)
    .execute(&db)
    .await
    .expect("record opt-out");

    let queue = sales_autopilot::actions::ActionQueue::new(db.clone(), "can-spam-test");
    let response = enrollments::start_outreach(
        &db,
        &queue,
        &tenant,
        &StartOutreachRequest {
            sequence_id: pending.sequence_id,
            contact_ids: vec![pending.contact_id],
            autonomy_policy_id: Some(pending.policy_id),
            experiment_id: None,
        },
    )
    .await
    .expect("outreach command succeeds; the rejection is reported, not an error");
    assert_eq!(response.accepted, 0, "a suppressed contact must not enroll");
    assert_eq!(response.rejected, 1);
    assert_eq!(
        response
            .rejection_reasons
            .get(sales_autopilot::enrollments::rejection_reason::SUPPRESSED),
        Some(&1),
        "rejection reasons: {:?}",
        response.rejection_reasons
    );
    let step_executions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sales_step_executions WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&db)
            .await
            .unwrap();
    let actions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(step_executions, 0, "no send work for a suppressed contact");
    assert_eq!(actions, 0, "no queued action for a suppressed contact");

    // ── Part B: suppression lands AFTER the step was queued ─────────────
    let enrolled =
        common::seed_sequence_fixture(&db, &tenant, common::SequenceFixtureOptions::default())
            .await;
    let step_execution_id = enrolled.step_execution_id.expect("fixture enrolls");
    sqlx::query(
        "INSERT INTO sales_unsubscribes (tenant_id, email) VALUES ($1, lower($2)) \
         ON CONFLICT (tenant_id, email) DO NOTHING",
    )
    .bind(&tenant)
    .bind(&enrolled.email)
    .execute(&db)
    .await
    .expect("record late opt-out");

    let outcome = common::run_send_step(
        &db,
        dispatcher_for(&db, &enrolled.domain),
        &tenant,
        step_execution_id,
    )
    .await;
    assert!(
        matches!(outcome, ActionOutcome::Succeeded),
        "a policy/gate denial is a recorded skip, not a retry: {outcome:?}"
    );

    let (state, skip_reason): (String, Option<String>) =
        sqlx::query_as("SELECT state, skip_reason FROM sales_step_executions WHERE id = $1")
            .bind(step_execution_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(state, "skipped");
    assert!(
        skip_reason.as_deref().unwrap_or("").contains("suppressed"),
        "the refusal must name the suppression: {skip_reason:?}"
    );
    let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&db)
        .await
        .unwrap();
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_queue WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        messages, 0,
        "suppressed recipient must never reach messages"
    );
    assert_eq!(
        queued, 0,
        "suppressed recipient must never reach email_queue"
    );

    common::cleanup_tenant(&db, &tenant).await;
}

/// The surviving frequency control is the per-account weekly touch budget
/// checked inside `decision_engine::decide`. A capped account's send is
/// refused while a fresh account still sends — the same funnel split the old
/// per-recipient cap test asserted.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn account_frequency_budget_blocks_over_mailing() {
    let Some(db) = common::test_pool("can_spam_frequency").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "can-spam-cap").await;

    let capped =
        common::seed_sequence_fixture(&db, &tenant, common::SequenceFixtureOptions::default())
            .await;
    let fresh =
        common::seed_sequence_fixture(&db, &tenant, common::SequenceFixtureOptions::default())
            .await;

    // Saturate the capped ACCOUNT's budget: the default budget is
    // `max(15, max_active_contacts * 5)` (decision_engine::
    // DEFAULT_WEEKLY_ACCOUNT_BUDGET / WEEKLY_BUDGET_PER_ACTIVE_CONTACT).
    for _ in 0..15 {
        sqlx::query(
            "INSERT INTO sales_outcomes (id, tenant_id, account_id, outcome, occurred_at) \
             VALUES (gen_random_uuid(), $1, $2, 'delivered', NOW())",
        )
        .bind(&tenant)
        .bind(capped.account_id)
        .execute(&db)
        .await
        .expect("record a delivered touch");
    }

    let capped_outcome = common::run_send_step(
        &db,
        dispatcher_for(&db, &capped.domain),
        &tenant,
        capped.step_execution_id.expect("fixture enrolls"),
    )
    .await;
    assert!(
        matches!(capped_outcome, ActionOutcome::Succeeded),
        "budget exhaustion is a recorded skip: {capped_outcome:?}"
    );
    let (state, skip_reason): (String, Option<String>) =
        sqlx::query_as("SELECT state, skip_reason FROM sales_step_executions WHERE id = $1")
            .bind(capped.step_execution_id.unwrap())
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(state, "skipped");
    assert!(
        skip_reason
            .as_deref()
            .unwrap_or("")
            .contains("account_frequency_budget_exhausted"),
        "the refusal must name the budget: {skip_reason:?}"
    );

    // The fresh account (same tenant, zero touches) still sends.
    let fresh_outcome = common::run_send_step(
        &db,
        dispatcher_for(&db, &fresh.domain),
        &tenant,
        fresh.step_execution_id.expect("fixture enrolls"),
    )
    .await;
    assert!(
        matches!(fresh_outcome, ActionOutcome::Succeeded),
        "{fresh_outcome:?}"
    );
    let fresh_queued: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM email_queue WHERE sales_step_execution_id = $1")
            .bind(fresh.step_execution_id.unwrap())
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(fresh_queued, 1, "the fresh account's recipient must send");
    let capped_queued: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM email_queue WHERE sales_step_execution_id = $1")
            .bind(capped.step_execution_id.unwrap())
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(capped_queued, 0, "the capped account must not be mailed");

    common::cleanup_tenant(&db, &tenant).await;
}

/// A deployment with no usable sales sender must fail loudly (and enqueue
/// nothing) rather than silently pretending to send. This replaces the old
/// "start without dispatcher is a loud ServiceUnavailable" test: campaign
/// start no longer dispatches (see `src/scheduler.rs` and
/// `routes::start_campaign`), so the surviving loud-failure point is sender
/// resolution on the sequence path.
#[tokio::test]
#[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
async fn missing_sales_sender_identity_fails_loudly() {
    let Some(db) = common::test_pool("can_spam_no_sender").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "can-spam-sender").await;
    let fx = common::seed_sequence_fixture(
        &db,
        &tenant,
        common::SequenceFixtureOptions::default().without_sender_identity(),
    )
    .await;
    let step_execution_id = fx.step_execution_id.expect("fixture enrolls");

    let outcome = common::run_send_step(
        &db,
        dispatcher_for(&db, &fx.domain),
        &tenant,
        step_execution_id,
    )
    .await;
    match outcome {
        ActionOutcome::Retry(reason) => assert!(
            reason.contains("no active sender identity"),
            "the retry must name the missing sender: {reason}"
        ),
        other => panic!("expected a loud Retry, got {other:?}"),
    }

    let state: String = sqlx::query_scalar("SELECT state FROM sales_step_executions WHERE id = $1")
        .bind(step_execution_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        state, "scheduled",
        "no sender means no send attempt, and the step stays retryable"
    );
    let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(messages, 0, "a misconfigured deployment sends nothing");

    common::cleanup_tenant(&db, &tenant).await;
}
