//! Release gates — audit item 27: gates that drive the REAL architecture.
//!
//! The previous suite asserted mostly at the data layer (column presence,
//! CHECK constraints, hand-written SQL). Those tests prove the schema is
//! shaped correctly; they do not prove any production code path consults it.
//! Every gate here drives the surviving call path end to end:
//!
//! ```text
//! /enrollments or /campaigns/:id/start (or a claimed sales_action)
//!   → SequenceStepHandler → decision_engine::decide
//!   → ProductionCampaignDispatcher::enqueue_sequenced
//!   → messages + email_queue
//! ```
//!
//! and the control-plane handlers (`control::review_decision`), the feedback
//! projector (`outcome_projector`), the reward ledger
//! (`experiments::record_reward`) and sender health (`sender_health`).
//!
//! A gate that only inspects schema is still useful, but it is labelled as
//! such in its doc comment — it is never dressed up as a call-path gate.
//!
//! # Gates covered elsewhere (index)
//!
//! These audit gates are deliberately NOT re-implemented in this file. The
//! named test is the authoritative coverage; it is cited so this suite stays
//! reviewable as a whole.
//!
//! * **12 — Discovery concurrency** (two runners on one job; the provider is
//!   called once per logical page). Covered by the live concurrency test
//!   `sales_autopilot::discovery::job::tests::concurrent_run_job_claims_once_and_calls_provider_once_per_page`
//!   (`crates/sales-autopilot/src/discovery/job.rs`): two `DiscoveryJobRunner`
//!   instances race `tokio::join!` on one job, assert exactly one claim wins,
//!   the provider is called exactly once, the loser gets the documented
//!   leased outcome, and exactly one `sales_source_runs` row exists. It is a
//!   real test, not a recipe, so this file does not duplicate it.
//! * **13 — Analytics boundary** (a send just before the window + an open
//!   inside it must not inflate the current-period open rate). Covered by
//!   `api_server::analytics_metrics::tests::cohort_boundaries_repeats_and_hostile_recipients`
//!   (`crates/api-server/src/analytics_metrics.rs`), which seeds exactly that
//!   out-of-window send/open pair and asserts the cohort open rate. It lives
//!   in `api-server` because the cohort SQL is `api-server`'s; reaching it
//!   from this crate would mean duplicating the query, which is the defect
//!   the gate exists to prevent.
//! * **14 — Previous-period freeze** (a send in the prior period + an open
//!   now must not retroactively alter the prior-period comparison). Covered by
//!   `api_server::analytics_metrics::tests::previous_period_is_frozen_at_its_own_end`
//!   (`crates/api-server/src/analytics_metrics.rs`), which asserts
//!   `previous.sent == 1`, `previous.opened == 0`, `open_rate == 0.0` through
//!   the real `send_cohort_counts_previous` query. Same crate boundary as 13.
//! * **15 — Dedicated delivery route** (selected IP A + receipt IP A
//!   succeeds; selected IP A + receipt IP B hard-fails). Covered in
//!   `worker-processors`:
//!   `worker_processors::email::processor::tests::route_verification_asymmetry_shared_ignores_dedicated_enforces`
//!   proves the exact-match/no-report hard failures, and
//!   `worker_processors::email::processor::tests::dedicated_route_mismatch_releases_the_warmup_reservation`
//!   drives `EmailProcessor::settle_delivery_route` end to end and proves the
//!   mismatched receipt errors and releases the reserved capacity. The
//!   processor is not reachable from this crate's public API.
//! * **16 — Feature-flag live behaviour** (flip a real flag; behaviour
//!   changes with no restart). Covered by
//!   `api_server::feature_flags::tests::disabled_route_rejects_until_admin_patch_enables_it`
//!   (`crates/api-server/src/feature_flags.rs`): the real AI-assistant route
//!   is rejected while the flag is off, an admin PATCH flips it, and the SAME
//!   `AppState` (same process) then permits the route.
//! * **17 — No runtime DDL** (a DML-only role can run the worker/reply
//!   processor). The real coverage is the source-scan test
//!   `worker_processors::reply_handler::processor::tests::reply_handler_issues_no_runtime_schema_ddl`
//!   (`crates/worker-processors/src/reply_handler/processor.rs`, item 23),
//!   which forbids `ALTER/CREATE/DROP TABLE` and `CREATE/DROP INDEX` in the
//!   reply worker source. NOTE (reported gap): this is a *source-scan* test,
//!   not a live run under a `NOINHERIT`/DML-only role; no live DML-only
//!   recipe or test was found anywhere in the workspace. The behaviour is
//!   only partially covered.
//! * **19 — System-health INET** (canonical-DB endpoint test). Covered by
//!   `api_server::routes::admin::system_health::tests::ip_pool_inet_column_serializes_as_dotted_quad`
//!   (`crates/api-server/src/routes/admin/system_health.rs`), which seeds a
//!   real `INET` row and drives the real `system_health` handler against the
//!   canonical pool. Not reachable from this crate.
//!
//! Gate 18 is implemented below (the in-module tests
//! `sales_autopilot::dispatcher::tests::token_is_opaque_no_plaintext_pii` and
//! `...::v2_token_url_carries_no_recipient_tenant_or_hex_payload` check
//! plaintext and hex only; this gate adds base64/URL-safe encodings and
//! asserts over the link the dispatcher actually emitted). Gate 20 (lead
//! indexes) is implemented below and explicitly labelled as a
//! deploy-contract/schema gate, which is the right tool for a `pg_indexes`
//! assertion.
//!
//! # Live-database contract
//!
//! Tests provision the crate's canonical pool (`tests/common/mod.rs`, which
//! builds the platform schema through the REAL production migrator). They
//! soft-skip only when no test database is configured; a configured
//! provisioning failure PANICS (F01). Every test uses its own tenant and
//! deletes its rows.

mod common;

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use uuid::Uuid;

use sales_autopilot::actions::{
    action_type, entity_type, verify_fence_in_tx, ActionFence, ActionOutcome, ActionQueue,
};
use sales_autopilot::decision_engine::{self, ContactPolicyInputOwned, DecisionContext};
use sales_autopilot::dispatcher::{
    send_idempotency_key, EnqueueOutcome, ProductionCampaignDispatcher, QuotaGateway,
    RenderedMessage, SendIdentity,
};
use sales_autopilot::outcome_projector::{OutcomeProjector, ProjectorConfig};
use sales_autopilot::sender_pool;
use sales_autopilot::types::{
    DecisionAction, Enforcement, OpportunityScore, SalesError, SenderPool,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type Fixture = (
    PgPool,
    String,
    common::SequenceFixture,
    Arc<ProductionCampaignDispatcher>,
);

/// The canonical sequence fixture plus a production dispatcher on its own
/// unique verified domain, with an allow-all quota gateway.
async fn fixture(test_name: &str, opts: common::SequenceFixtureOptions) -> Option<Fixture> {
    let db = common::test_pool(test_name).await?;
    let tenant_id = common::insert_test_tenant(&db, test_name).await;
    let seq = common::seed_sequence_fixture(&db, &tenant_id, opts).await;
    let dispatcher = Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(&seq.domain),
            db.clone(),
            Arc::new(common::AllowAllQuotaGateway) as Arc<dyn QuotaGateway>,
        )
        .expect("test dispatch config must be valid"),
    );
    Some((db, tenant_id, seq, dispatcher))
}

/// `(messages, email_queue)` rows for one tenant.
async fn effect_counts(db: &PgPool, tenant_id: &str) -> (i64, i64) {
    let messages: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM messages WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(db)
            .await
            .expect("count messages");
    let queued: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM email_queue WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(db)
            .await
            .expect("count email_queue");
    (messages, queued)
}

/// `(messages, email_queue)` rows for one step execution.
async fn step_effect_counts(db: &PgPool, step_execution_id: Uuid) -> (i64, i64) {
    let messages: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages WHERE sales_step_execution_id = $1",
    )
    .bind(step_execution_id)
    .fetch_one(db)
    .await
    .expect("count step messages");
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue WHERE sales_step_execution_id = $1",
    )
    .bind(step_execution_id)
    .fetch_one(db)
    .await
    .expect("count step queue rows");
    (messages, queued)
}

async fn step_state(db: &PgPool, step_execution_id: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT state, skip_reason FROM sales_step_executions WHERE id = $1")
        .bind(step_execution_id)
        .fetch_one(db)
        .await
        .expect("read step execution")
}

/// Insert (or update) the authoritative email policy for one jurisdiction.
///
/// Test-scoped jurisdiction codes (`XR`/`XS`/`XT`/`XU`) are deliberately
/// outside the ISO EU/EEA set and outside the shared fixture's `QZ`, so
/// parallel suites can never observe these rows, and each test owns its own
/// code so parallel runs never delete each other's policy.
async fn upsert_email_policy(db: &PgPool, jurisdiction: &str, decision: &str, basis: &str) {
    sqlx::query(
        "INSERT INTO sales_jurisdiction_policies \
             (id, jurisdiction, channel, contact_type, decision, basis, version, \
              approved_by, approved_at, valid_from) \
         VALUES (gen_random_uuid(), $1, 'email', 'b2b_professional', $2, $3, 1, \
                 'release-gate-test', NOW(), NOW()) \
         ON CONFLICT (jurisdiction, channel, contact_type, version) DO UPDATE \
             SET decision = EXCLUDED.decision, basis = EXCLUDED.basis, \
                 approved_by = EXCLUDED.approved_by, approved_at = EXCLUDED.approved_at, \
                 valid_from = EXCLUDED.valid_from",
    )
    .bind(jurisdiction)
    .bind(decision)
    .bind(basis)
    .execute(db)
    .await
    .unwrap_or_else(|error| panic!("upsert policy for {jurisdiction} failed: {error}"));
}

async fn delete_policy(db: &PgPool, jurisdiction: &str) {
    let _ = sqlx::query("DELETE FROM sales_jurisdiction_policies WHERE jurisdiction = $1")
        .bind(jurisdiction)
        .execute(db)
        .await;
}

async fn set_account_country(db: &PgPool, account_id: Uuid, country: &str) {
    sqlx::query("UPDATE sales_accounts SET country = $2, country_confidence = 0.95 WHERE id = $1")
        .bind(account_id)
        .bind(country)
        .execute(db)
        .await
        .expect("set fixture account country");
}

fn zero_score() -> OpportunityScore {
    OpportunityScore {
        account_fit: 50.0,
        persona_fit: 50.0,
        need_fit: 50.0,
        intent: 50.0,
        timing: 50.0,
        email_stack_fit: 50.0,
        eu_residency_fit: 0.0,
        reachability: 80.0,
        evidence_quality: 50.0,
        legal_contactability: 80.0,
        risk: 10.0,
        p_qualified_reply: 0.1,
        p_meeting: 0.05,
        p_paid: 0.01,
        expected_value_eur: 100.0,
        total: 55.0,
        reason_codes: vec!["release-gate-test".to_string()],
        scoring_version: "release-gate-v1".to_string(),
    }
}

/// The canonical allowed policy input for `TEST_JURISDICTION`.
fn allowed_policy_input(seq: &common::SequenceFixture) -> ContactPolicyInputOwned {
    ContactPolicyInputOwned {
        account_id: Some(seq.account_id),
        contact_id: Some(seq.contact_id),
        contact_point_id: Some(seq.contact_point_id),
        recipient_country: Some(common::TEST_JURISDICTION.to_string()),
        country_confidence: 0.95,
        contact_type: "b2b_professional".to_string(),
        channel: "email".to_string(),
        source: Some("release-gate".to_string()),
        purpose: Some("outbound_sales".to_string()),
        has_existing_relationship: false,
        consent_status: None,
        soft_opt_in: false,
        legitimate_interest_assessed: true,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Gate 1 — legal bypass
// ---------------------------------------------------------------------------

/// Gate 1: "Legal bypass — a prohibited contact is never mailed, whichever
/// sales route is used."
///
/// Drives the three real entry points in order:
/// 1. `enrollments::start_outreach` (the `/enrollments` command) — rejected
///    with the `legal_policy` reason;
/// 2. `CampaignManager::start_campaign_with_outreach` (the legacy
///    `/campaigns/:id/start` route) — refused before any enrollment;
/// 3. the durable worker (`SequenceStepHandler`) over a queued step action —
///    the decision engine refuses and records the denial.
///
/// Then asserts ZERO `messages` and ZERO `email_queue` rows.
#[tokio::test]
async fn gate_01_prohibited_contact_is_refused_by_every_route_and_by_the_worker() {
    let Some((db, tenant_id, seq, dispatcher)) = fixture(
        "gate01_legal_bypass",
        common::SequenceFixtureOptions::default(),
    )
    .await
    else {
        return;
    };
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");

    // The contact resolves to a PROHIBITED jurisdiction (`XR` is not an
    // EU/EEA code, so it keeps its own policy key).
    upsert_email_policy(&db, "XR", "prohibited", "not_permitted").await;
    set_account_country(&db, seq.account_id, "XR").await;
    let account_domain: String =
        sqlx::query_scalar("SELECT domain FROM sales_accounts WHERE id = $1")
            .bind(seq.account_id)
            .fetch_one(&db)
            .await
            .expect("fixture account domain");
    let prohibited_email = format!("prohibited@{account_domain}");
    sqlx::query(
        "UPDATE sales_contact_points SET value = $2, normalized_value = lower($2) WHERE id = $1",
    )
    .bind(seq.contact_point_id)
    .bind(&prohibited_email)
    .execute(&db)
    .await
    .expect("point the fixture contact at the prohibited account's domain");

    // ── Route 1: the canonical outreach command (`POST /enrollments`) ──────
    let queue = ActionQueue::new(db.clone(), format!("gate01-enroll-{tenant_id}"));
    let response = sales_autopilot::enrollments::start_outreach(
        &db,
        &queue,
        &tenant_id,
        &sales_autopilot::enrollments::StartOutreachRequest {
            sequence_id: seq.sequence_id,
            contact_ids: vec![seq.contact_id],
            autonomy_policy_id: seq.policy_id,
            experiment_id: None,
        },
    )
    .await
    .expect("the command itself succeeds; the legal gate rejects the contact");
    assert_eq!(
        response.accepted, 0,
        "a prohibited contact cannot be enrolled"
    );
    assert_eq!(response.rejected, 1);
    assert_eq!(
        response
            .rejection_reasons
            .get(sales_autopilot::enrollments::rejection_reason::LEGAL_POLICY)
            .copied(),
        Some(1),
        "the rejection must name the legal gate: {:?}",
        response.rejection_reasons
    );

    // ── Route 2: the legacy campaign start (`POST /campaigns/:id/start`) ───
    let manager = sales_autopilot::campaigns::CampaignManager::new(50, db.clone());
    let template_id = seq.template_id.clone().expect("fixture seeds a template");
    let campaign = manager
        .create_campaign(
            tenant_id.clone(),
            "Prohibited recipient".to_string(),
            template_id,
            "gate-01".to_string(),
        )
        .await
        .expect("create the legacy campaign");
    manager
        .add_recipients(&tenant_id, campaign.id, vec![prohibited_email.clone()])
        .await
        .expect("add the prohibited recipient");
    let started = manager
        .start_campaign_with_outreach(&tenant_id, campaign.id)
        .await;
    match started {
        Err(SalesError::PolicyDenied(reason)) => assert!(
            reason.contains("'XR'"),
            "the legacy route must refuse the prohibited jurisdiction, got: {reason}"
        ),
        Ok((_, outreach)) => panic!(
            "the legacy campaign route must refuse before enrollment, got outreach {outreach:?}"
        ),
        Err(other) => panic!("expected PolicyDenied from the legacy route, got {other:?}"),
    }

    // Neither route may have left a queued action behind.
    let queued_actions: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&db)
            .await
            .expect("count actions");
    assert_eq!(
        queued_actions, 0,
        "a refused contact must not leave queued outbound work"
    );

    // ── Route 3: the real worker over a queued step action ────────────────
    // Even if a bypass queued the work, the decision engine is the last gate.
    let outcome =
        common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert!(
        matches!(outcome, ActionOutcome::Succeeded),
        "a denial is a terminal skip, not a retry: {outcome:?}"
    );
    let (state, reason) = step_state(&db, step_execution_id).await;
    assert_eq!(state, "skipped");
    assert!(
        reason
            .as_deref()
            .unwrap_or_default()
            .contains("legal_policy_prohibited"),
        "the worker must record the legal refusal, got: {reason:?}"
    );

    assert_eq!(
        effect_counts(&db, &tenant_id).await,
        (0, 0),
        "a prohibited contact must produce zero messages and zero queue rows"
    );

    common::cleanup_tenant(&db, &tenant_id).await;
    delete_policy(&db, "XR").await;
}

// ---------------------------------------------------------------------------
// Gate 2 — decision coverage
// ---------------------------------------------------------------------------

/// Gate 2: "Every `email_queue` row tagged `sales-sequence` carries the full
/// Decision Packet provenance."
///
/// A real send is driven first; the assertion is over the row the dispatcher
/// emitted, never over a hand-inserted one.
#[tokio::test]
async fn gate_02_every_sequence_email_queue_row_carries_full_decision_provenance() {
    let Some((db, tenant_id, seq, dispatcher)) = fixture(
        "gate02_provenance",
        common::SequenceFixtureOptions::default(),
    )
    .await
    else {
        return;
    };
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");

    let outcome =
        common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");

    let tagged: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue \
         WHERE tenant_id = $1 AND tags @> ARRAY['sales-sequence']::text[]",
    )
    .bind(&tenant_id)
    .fetch_one(&db)
    .await
    .expect("count tagged queue rows");
    assert!(
        tagged >= 1,
        "the real send must have emitted a sales-sequence queue row"
    );

    let missing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue \
         WHERE tenant_id = $1 AND tags @> ARRAY['sales-sequence']::text[] \
           AND (sales_decision_id IS NULL \
                OR sales_sender_identity_id IS NULL \
                OR sales_step_execution_id IS NULL \
                OR sales_enrollment_id IS NULL)",
    )
    .bind(&tenant_id)
    .fetch_one(&db)
    .await
    .expect("count rows missing provenance");
    assert_eq!(
        missing, 0,
        "every emitted sequence queue row must link decision, sender, step execution and enrollment"
    );

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Gate 3 — transactional-pool isolation
// ---------------------------------------------------------------------------

/// Gate 3: "A sequence send never selects a transactional/customer sender."
///
/// Seeds a `transactional_customer` sender *and* one `sales_outbound` sender;
/// the sequence requests `sales_outbound` and the emitted envelope must be the
/// sales identity, never the transactional one.
#[tokio::test]
async fn gate_03_sequence_send_never_selects_the_transactional_sender() {
    let identity_domain = common::unique_test_domain();
    let Some((db, tenant_id, seq, dispatcher)) = fixture(
        "gate03_sender_isolation",
        common::SequenceFixtureOptions::default().with_identity_domain(identity_domain.clone()),
    )
    .await
    else {
        return;
    };
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");

    // A transactional sender is present and active — it must simply never be
    // selected by a sales action.
    let transactional_email = "billing@customer.example";
    common::insert_sender_identity(
        &db,
        &tenant_id,
        "transactional_customer",
        transactional_email,
        "customer.example",
        "active",
    )
    .await;

    let outcome =
        common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");

    let from_addresses: Vec<String> =
        sqlx::query_scalar("SELECT from_address FROM email_queue WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_all(&db)
            .await
            .expect("read emitted envelopes");
    assert_eq!(from_addresses.len(), 1, "exactly one send");
    assert_eq!(
        from_addresses[0], seq.sender_from_email,
        "the envelope must be the resolved sales identity"
    );
    assert_eq!(from_addresses[0], format!("sales@{identity_domain}"));
    assert_ne!(
        from_addresses[0],
        dispatcher.config().from_email,
        "the deployment-wide default must not be the sender"
    );
    assert_ne!(from_addresses[0], transactional_email);

    let leaked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue \
         WHERE tenant_id = $1 AND (from_address = $2 OR \"from\" = $2)",
    )
    .bind(&tenant_id)
    .bind(transactional_email)
    .fetch_one(&db)
    .await
    .expect("count transactional senders");
    assert_eq!(
        leaked, 0,
        "the transactional address must never appear on a sales send"
    );

    // Isolation, not deletion: the transactional identity still exists.
    let still_there: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sales_sender_identities \
         WHERE tenant_id = $1 AND from_email = $2)",
    )
    .bind(&tenant_id)
    .bind(transactional_email)
    .fetch_one(&db)
    .await
    .expect("transactional identity lookup");
    assert!(still_there);

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Gate 4 — no sender available
// ---------------------------------------------------------------------------

/// Gate 4: "With no sales sender, the action retries and writes nothing."
///
/// Only a transactional sender exists. The documented outcome is a RETRY
/// (the send resumes once a sales identity is provisioned) — never a silent
/// success — and no external effect is produced.
#[tokio::test]
async fn gate_04_missing_sales_sender_is_a_retry_with_no_external_effect() {
    let Some((db, tenant_id, seq, dispatcher)) = fixture(
        "gate04_no_sender",
        common::SequenceFixtureOptions::default().without_sender_identity(),
    )
    .await
    else {
        return;
    };
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");

    common::insert_sender_identity(
        &db,
        &tenant_id,
        "transactional_customer",
        "billing@customer.example",
        "customer.example",
        "active",
    )
    .await;

    let outcome =
        common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    match &outcome {
        ActionOutcome::Retry(reason) => assert!(
            reason.contains("no active sender identity"),
            "the retry must name the missing pool, got: {reason}"
        ),
        other => panic!("no sales sender must be a retry, got {other:?}"),
    }

    assert_eq!(
        effect_counts(&db, &tenant_id).await,
        (0, 0),
        "a missing sender must not enqueue anything"
    );
    let decisions: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_decisions WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&db)
            .await
            .expect("count decisions");
    assert_eq!(
        decisions, 0,
        "sender resolution must fail before a Decision Packet is produced"
    );

    let (state, attempt, last_error): (String, i32, Option<String>) =
        sqlx::query_as("SELECT state, attempt, last_error FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&db)
            .await
            .expect("read the action");
    assert_eq!(state, "queued", "the work is retryable, not lost");
    assert_eq!(attempt, 1);
    assert!(last_error
        .as_deref()
        .unwrap_or_default()
        .contains("no active sender identity"));

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Gate 5 — approval flow
// ---------------------------------------------------------------------------

/// Gate 5 (approve): "await_approval → no mail; after approval → exactly one
/// mail."
///
/// Drives `control::review_decision` (the real handler) rather than writing
/// the review state by hand.
#[tokio::test]
async fn gate_05_approval_releases_exactly_one_approved_send() {
    let Some((db, tenant_id, seq, dispatcher)) =
        fixture("gate05_approval", common::SequenceFixtureOptions::default()).await
    else {
        return;
    };
    upsert_email_policy(&db, "XS", "approval_required", "legitimate_interest").await;
    set_account_country(&db, seq.account_id, "XS").await;
    common::seed_open_opportunity(&db, &tenant_id, seq.account_id, 100_000.0).await;
    common::seed_live_evidence(&db, &tenant_id, seq.account_id, 3).await;
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");

    // 1) The legal gate forces a human: no mail, the action parks.
    let first = common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert_eq!(
        first,
        ActionOutcome::AwaitApproval,
        "an approval-required policy must park the work"
    );
    assert_eq!(effect_counts(&db, &tenant_id).await, (0, 0));

    let (decision_id, enforcement, review_status): (Uuid, String, Option<String>) = sqlx::query_as(
        "SELECT id, enforcement, review_status FROM sales_decisions \
         WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(&tenant_id)
    .fetch_one(&db)
    .await
    .expect("the parked decision");
    assert_eq!(enforcement, "await_approval");
    assert_eq!(review_status.as_deref(), Some("pending"));
    let parked_state: String =
        sqlx::query_scalar("SELECT state FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&db)
            .await
            .expect("the parked action");
    assert_eq!(parked_state, "awaiting_approval");

    // 2) The operator approves through the REAL control handler.
    let body = common::review_decision(
        &db,
        &tenant_id,
        decision_id,
        "approved",
        Some("release gate 05"),
    )
    .await
    .expect("the review handler must succeed");
    assert_eq!(body["outcome"], "approved", "review response: {body}");
    assert!(
        body["revalidation"]["allowed"].as_bool().unwrap_or(false),
        "the gates must permit the released work: {body}"
    );
    assert_eq!(
        body["actionsAffected"].as_u64(),
        Some(1),
        "review response: {body}"
    );
    let released: (String, i32) =
        sqlx::query_as("SELECT state, attempt FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&db)
            .await
            .expect("the released action");
    assert_eq!(released, ("queued".to_string(), 0));

    // 3) The SAME worker path executes the approved work exactly once.
    let second =
        common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert!(
        matches!(second, ActionOutcome::Succeeded),
        "approved work must execute, got {second:?}"
    );
    assert_eq!(
        effect_counts(&db, &tenant_id).await,
        (1, 1),
        "approval must release exactly one logical send"
    );

    common::cleanup_tenant(&db, &tenant_id).await;
    delete_policy(&db, "XS").await;
}

/// Gate 5 (reject): "after rejection → zero mail."
///
/// Rejection cancels the linked action through `control::review_decision`;
/// nothing is sent and nothing remains claimable.
#[tokio::test]
async fn gate_05_rejection_cancels_the_work_and_sends_nothing() {
    let Some((db, tenant_id, seq, dispatcher)) = fixture(
        "gate05_rejection",
        common::SequenceFixtureOptions::default(),
    )
    .await
    else {
        return;
    };
    upsert_email_policy(&db, "XU", "approval_required", "legitimate_interest").await;
    set_account_country(&db, seq.account_id, "XU").await;
    common::seed_open_opportunity(&db, &tenant_id, seq.account_id, 100_000.0).await;
    common::seed_live_evidence(&db, &tenant_id, seq.account_id, 3).await;
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");

    let first = common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert_eq!(first, ActionOutcome::AwaitApproval);
    let decision_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM sales_decisions WHERE tenant_id = $1 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(&tenant_id)
    .fetch_one(&db)
    .await
    .expect("the parked decision");

    let body = common::review_decision(&db, &tenant_id, decision_id, "rejected", Some("not now"))
        .await
        .expect("the review handler must succeed");
    assert_eq!(body["outcome"], "rejected", "review response: {body}");
    assert_eq!(
        body["revalidation"]["allowed"].as_bool(),
        Some(false),
        "a rejection is not an allowed execution: {body}"
    );

    let state: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE tenant_id = $1")
        .bind(&tenant_id)
        .fetch_one(&db)
        .await
        .expect("the rejected action");
    assert_eq!(state, "cancelled");
    let claimable: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_actions \
         WHERE tenant_id = $1 AND state IN ('queued', 'leased', 'executing', 'awaiting_approval')",
    )
    .bind(&tenant_id)
    .fetch_one(&db)
    .await
    .expect("count claimable actions");
    assert_eq!(claimable, 0, "rejected work must not remain claimable");
    assert_eq!(effect_counts(&db, &tenant_id).await, (0, 0));

    common::cleanup_tenant(&db, &tenant_id).await;
    delete_policy(&db, "XU").await;
}

// ---------------------------------------------------------------------------
// Gate 6 — approval race
// ---------------------------------------------------------------------------

/// Gate 6: "Approval is not a bypass — approve, THEN unsubscribe, THEN let the
/// worker execute → zero mail."
///
/// The kill switch / suppression must win even over a human approval that
/// landed first.
#[tokio::test]
async fn gate_06_approval_does_not_bypass_a_later_unsubscribe() {
    let Some((db, tenant_id, seq, dispatcher)) = fixture(
        "gate06_approval_race",
        common::SequenceFixtureOptions::default(),
    )
    .await
    else {
        return;
    };
    upsert_email_policy(&db, "XT", "approval_required", "legitimate_interest").await;
    set_account_country(&db, seq.account_id, "XT").await;
    common::seed_open_opportunity(&db, &tenant_id, seq.account_id, 100_000.0).await;
    common::seed_live_evidence(&db, &tenant_id, seq.account_id, 3).await;
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");

    let first = common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert_eq!(first, ActionOutcome::AwaitApproval);
    let decision_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM sales_decisions WHERE tenant_id = $1 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(&tenant_id)
    .fetch_one(&db)
    .await
    .expect("the parked decision");
    let body = common::review_decision(
        &db,
        &tenant_id,
        decision_id,
        "approved",
        Some("approved first"),
    )
    .await
    .expect("approval succeeds at the moment it is given");
    assert_eq!(body["outcome"], "approved");

    // The unsubscribe lands AFTER the approval and BEFORE execution.
    ProductionCampaignDispatcher::suppress(&db, &tenant_id, &seq.email, "unsubscribe-link")
        .await
        .expect("the real suppression path");

    let second =
        common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert!(
        matches!(second, ActionOutcome::Succeeded),
        "the refusal is a terminal skip: {second:?}"
    );
    assert_eq!(
        effect_counts(&db, &tenant_id).await,
        (0, 0),
        "an approval must not bypass an unsubscribe that landed after it"
    );

    let latest_reasons: serde_json::Value = sqlx::query_scalar(
        "SELECT block_reasons FROM sales_decisions WHERE tenant_id = $1 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(&tenant_id)
    .fetch_one(&db)
    .await
    .expect("the post-approval decision");
    assert!(
        latest_reasons.to_string().contains("suppressed"),
        "the refusal must record the suppression, got {latest_reasons}"
    );

    common::cleanup_tenant(&db, &tenant_id).await;
    delete_policy(&db, "XT").await;
}

// ---------------------------------------------------------------------------
// Gate 7 — lease expiry chaos
// ---------------------------------------------------------------------------

/// Gate 7: "Worker A sleeps past its lease; worker B recovers; A's stale token
/// fails the dispatcher fence; exactly ONE logical message exists."
///
/// Drives `ActionQueue` claims, `requeue_expired_leases`,
/// `verify_fence_in_tx` and `ProductionCampaignDispatcher::enqueue_sequenced`.
#[tokio::test]
async fn gate_07_expired_lease_recovery_fences_the_stale_worker_to_one_message() {
    let Some((db, tenant_id, seq, dispatcher)) = fixture(
        "gate07_lease_chaos",
        common::SequenceFixtureOptions::default(),
    )
    .await
    else {
        return;
    };
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");
    let enrollment_id = seq.enrollment_id.expect("fixture enrolls");

    let action = common::enqueue_send_step_action(&db, &tenant_id, step_execution_id).await;

    // Worker A claims, then "sleeps" past its lease (we shorten the lease so
    // the test takes milliseconds instead of two minutes).
    let worker_a = common::claim_specific_action(&db, "gate07-worker-a", action.id)
        .await
        .expect("worker A claims");
    sqlx::query(
        "UPDATE sales_actions SET lease_expires_at = NOW() - INTERVAL '2 seconds' WHERE id = $1",
    )
    .bind(action.id)
    .execute(&db)
    .await
    .expect("expire worker A's lease");
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Worker B recovers the expired work.
    let recovered = sales_autopilot::actions::requeue_expired_leases(&db)
        .await
        .expect("the recovery sweep");
    assert!(recovered >= 1, "the expired lease must be recovered");
    let worker_b = common::claim_specific_action(&db, "gate07-worker-b", action.id)
        .await
        .expect("worker B recovers the action");
    assert_eq!(worker_b.id(), action.id);

    // A's fence must fail the transactional fence check...
    let mut tx = db.begin().await.expect("begin tx");
    assert!(
        !verify_fence_in_tx(&mut tx, &worker_a.fence())
            .await
            .expect("fence check"),
        "worker A's stale fence must not authorize work"
    );
    // ...while B's is live.
    let mut tx_b = db.begin().await.expect("begin tx");
    assert!(
        verify_fence_in_tx(&mut tx_b, &worker_b.fence())
            .await
            .expect("fence check"),
        "worker B's fence must be live"
    );
    tx_b.rollback().await.ok();
    drop(tx);

    let sender = sender_pool::resolve_sales_sender(&db, &tenant_id, SenderPool::SalesOutbound)
        .await
        .expect("fixture sales sender resolves");
    let decision_id = common::insert_fixture_decision(&db, &tenant_id).await;
    let rendered = RenderedMessage {
        subject: "lease chaos".to_string(),
        html: Some("<p>lease chaos</p>".to_string()),
        text: Some("lease chaos".to_string()),
    };
    let key = send_idempotency_key(SendIdentity::StepExecution {
        enrollment_id,
        sequence_version_id: seq.version_id,
        step_id: seq.step_id,
        attempt_kind: "primary",
        variant: "default",
    });

    // A's old token must be refused by the DISPATCHER fence, with no effect.
    let stale = dispatcher
        .enqueue_sequenced(
            &tenant_id,
            &key,
            &rendered,
            &seq.email,
            "https://sales.example.com/u/fixture-token",
            &sender,
            decision_id,
            step_execution_id,
            enrollment_id,
            &worker_a.fence(),
            serde_json::json!({ "gate": 7 }),
        )
        .await
        .expect("the stale call itself returns an outcome");
    assert_eq!(
        stale,
        EnqueueOutcome::LeaseLost,
        "a recovered worker's fence must not produce an external effect"
    );
    assert_eq!(step_effect_counts(&db, step_execution_id).await, (0, 0));

    // B's live token produces exactly one logical message.
    let fresh = dispatcher
        .enqueue_sequenced(
            &tenant_id,
            &key,
            &rendered,
            &seq.email,
            "https://sales.example.com/u/fixture-token",
            &sender,
            decision_id,
            step_execution_id,
            enrollment_id,
            &worker_b.fence(),
            serde_json::json!({ "gate": 7 }),
        )
        .await
        .expect("the recovered worker sends");
    assert_eq!(fresh, EnqueueOutcome::Enqueued);
    assert_eq!(
        step_effect_counts(&db, step_execution_id).await,
        (1, 1),
        "exactly one logical message must exist after recovery"
    );
    let distinct_keys: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT idempotency_key)::bigint FROM messages \
         WHERE sales_step_execution_id = $1",
    )
    .bind(step_execution_id)
    .fetch_one(&db)
    .await
    .expect("count logical messages");
    assert_eq!(distinct_keys, 1);

    // B owns the action; it completes with its live fence.
    let queue_b = ActionQueue::new(db.clone(), worker_b.lease_owner.clone());
    assert!(
        queue_b
            .finish(&worker_b.fence(), ActionOutcome::Succeeded)
            .await
            .expect("finish"),
        "worker B still owns its lease"
    );

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Gate 8 — replica IDs
// ---------------------------------------------------------------------------

/// Gate 8: "Two simulated PID-1 replicas produce distinct worker identities."
///
/// GAP: `bin/server.rs::unique_worker_id` is PRIVATE, so the exact string
/// cannot be produced from this crate. The gate therefore asserts the
/// property the id exists for — owner strings must be per-process unique and a
/// worker must never complete another worker's claim — on the real
/// `ActionQueue` owner/fence handling, and pins the generator's ingredients by
/// source scan (hostname + PID + random UUID).
#[tokio::test]
async fn gate_08_replica_worker_identities_are_distinct_and_fences_are_per_claim() {
    let Some(db) = common::test_pool("gate08_replica_ids").await else {
        return;
    };
    let tenant_id = common::insert_test_tenant(&db, "gate08").await;
    let queue = ActionQueue::new(db.clone(), "gate08-seeder");

    let first = queue
        .enqueue(
            &tenant_id,
            action_type::RESCORE,
            entity_type::ACCOUNT,
            Uuid::new_v4(),
            &format!("gate08:{tenant_id}:1"),
            serde_json::json!({}),
            chrono::Utc::now() - chrono::Duration::seconds(1),
            100,
            None,
        )
        .await
        .expect("enqueue first");
    let second = queue
        .enqueue(
            &tenant_id,
            action_type::RESCORE,
            entity_type::ACCOUNT,
            Uuid::new_v4(),
            &format!("gate08:{tenant_id}:2"),
            serde_json::json!({}),
            chrono::Utc::now() - chrono::Duration::seconds(1),
            100,
            None,
        )
        .await
        .expect("enqueue second");

    // Simulate two replicas that share a hostname and PID (separate containers
    // routinely do) but carry different random suffixes — exactly what
    // `unique_worker_id` composes.
    let owner_a = format!("gate-host:1:{}", Uuid::new_v4());
    let owner_b = format!("gate-host:1:{}", Uuid::new_v4());
    assert_ne!(owner_a, owner_b);
    let claim_a = common::claim_specific_action(&db, &owner_a, first.id)
        .await
        .expect("replica A claims");
    let claim_b = common::claim_specific_action(&db, &owner_b, second.id)
        .await
        .expect("replica B claims");
    assert_ne!(claim_a.lease_owner, claim_b.lease_owner);
    assert_ne!(
        claim_a.lease_token, claim_b.lease_token,
        "each claim must carry its own token"
    );
    let owners: Vec<String> = sqlx::query_scalar(
        "SELECT lease_owner FROM sales_actions WHERE tenant_id = $1 ORDER BY id",
    )
    .bind(&tenant_id)
    .fetch_all(&db)
    .await
    .expect("read lease owners");
    assert_eq!(owners.len(), 2);
    assert_ne!(
        owners[0], owners[1],
        "two replicas must not share an owner id"
    );
    assert!(owners.contains(&owner_a) && owners.contains(&owner_b));

    // The queue handle's own worker id is irrelevant: the FENCE is the
    // authority. A fence naming the other replica's owner must be refused...
    let owner_queue = ActionQueue::new(db.clone(), owner_a.clone());
    let wrong_owner = ActionFence {
        action_id: claim_a.id(),
        lease_owner: claim_b.lease_owner.clone(),
        lease_token: claim_a.lease_token,
    };
    assert!(
        !owner_queue
            .finish(&wrong_owner, ActionOutcome::Succeeded)
            .await
            .expect("finish"),
        "another replica's owner id must fail the fence"
    );
    // ...and so must a forged per-claim token under the right owner.
    let forged = ActionFence {
        action_id: claim_a.id(),
        lease_owner: claim_a.lease_owner.clone(),
        lease_token: Uuid::new_v4(),
    };
    assert!(
        !owner_queue
            .finish(&forged, ActionOutcome::Succeeded)
            .await
            .expect("finish"),
        "a forged per-claim token must fail the fence"
    );
    // The real owner completes it.
    assert!(
        owner_queue
            .finish(&claim_a.fence(), ActionOutcome::Succeeded)
            .await
            .expect("finish"),
        "the owning replica must be able to complete its own claim"
    );
    let state: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
        .bind(first.id)
        .fetch_one(&db)
        .await
        .expect("read state");
    assert_eq!(state, "succeeded");

    // The private generator's ingredients, pinned by source scan: hostname +
    // PID alone are NOT unique across containers, so a random UUID is
    // required. (See the gate doc comment for the reachability gap.)
    let server_source = include_str!("../src/bin/server.rs");
    assert!(
        server_source.contains("std::env::var(\"HOSTNAME\")")
            && server_source.contains("std::process::id()")
            && server_source.contains("uuid::Uuid::new_v4()"),
        "the replica id must combine hostname, PID and a random UUID"
    );

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Gate 9 — no-dispatcher preservation
// ---------------------------------------------------------------------------

/// Gate 9: "Without a dispatcher, queued send_step work is preserved."
///
/// `bin/server.rs` does not start the action worker at all when the dispatcher
/// is unconfigured. This gate asserts the queue-level contract over a real
/// queue: the action stays `queued`, is never claimed (`attempt = 0`, no
/// lease) and is never dead-lettered.
#[tokio::test]
async fn gate_09_without_a_dispatcher_queued_work_is_preserved() {
    let Some((db, tenant_id, seq, _dispatcher)) = fixture(
        "gate09_no_dispatcher",
        common::SequenceFixtureOptions::default(),
    )
    .await
    else {
        return;
    };
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");
    let action = common::enqueue_send_step_action(&db, &tenant_id, step_execution_id).await;

    // The server's no-dispatcher branch never constructs a handler or calls
    // `claim`; the recovery sweep is the only thing that touches the queue in
    // a tick, and it must leave queued work alone.
    let _ = sales_autopilot::actions::requeue_expired_leases(&db)
        .await
        .expect("the recovery sweep");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (state, attempt, owner, token, expires, completed): (
        String,
        i32,
        Option<String>,
        Option<Uuid>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT state, attempt, lease_owner, lease_token, lease_expires_at, completed_at \
         FROM sales_actions WHERE id = $1",
    )
    .bind(action.id)
    .fetch_one(&db)
    .await
    .expect("read preserved action");
    assert_eq!(state, "queued", "queued work must remain queued");
    assert_eq!(attempt, 0, "the action must never have been claimed");
    assert_eq!(owner, None);
    assert_eq!(token, None);
    assert_eq!(expires, None);
    assert_eq!(completed, None, "queued work is not complete");

    let stats = ActionQueue::new(db.clone(), "gate09-observer")
        .stats(&tenant_id)
        .await
        .expect("queue stats");
    assert_eq!(
        stats["deadLettered"].as_i64(),
        Some(0),
        "nothing may be dead-lettered: {stats}"
    );
    assert!(
        stats["dueNow"].as_i64().unwrap_or(0) >= 1,
        "the preserved action is still due: {stats}"
    );
    assert_eq!(effect_counts(&db, &tenant_id).await, (0, 0));

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Gate 10 — reward loop
// ---------------------------------------------------------------------------

/// Gate 10: "A real send chooses a variant; the outcome projector moves that
/// arm's posterior ONCE; replaying the same outcome leaves it unchanged."
///
/// Drives `SequenceStepHandler` (variant selection), `OutcomeProjector` and
/// `experiments::record_reward`.
#[tokio::test]
async fn gate_10_reward_projection_moves_the_posterior_once_and_replay_is_a_noop() {
    let Some((db, tenant_id, seq, dispatcher)) = fixture(
        "gate10_reward_loop",
        common::SequenceFixtureOptions::default(),
    )
    .await
    else {
        return;
    };
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");
    let enrollment_id = seq.enrollment_id.expect("fixture enrolls");

    // A running experiment with two arms, declared on the step.
    let experiment_id = Uuid::new_v4();
    let experiment_key = format!("gate10-exp-{tenant_id}");
    sqlx::query(
        "INSERT INTO sales_experiments (id, tenant_id, key, name, status) \
         VALUES ($1, $2, $3, 'Gate 10 experiment', 'running')",
    )
    .bind(experiment_id)
    .bind(&tenant_id)
    .bind(&experiment_key)
    .execute(&db)
    .await
    .expect("insert experiment");
    for variant in ["a", "b"] {
        sqlx::query(
            "INSERT INTO sales_experiment_arms \
                 (id, tenant_id, experiment_id, variant, is_control) \
             VALUES (gen_random_uuid(), $1, $2, $3, $4)",
        )
        .bind(&tenant_id)
        .bind(experiment_id)
        .bind(variant)
        .bind(variant == "a")
        .execute(&db)
        .await
        .expect("insert arm");
    }
    sqlx::query("UPDATE sales_sequence_steps SET experiment_key = $2 WHERE id = $1")
        .bind(seq.step_id)
        .bind(&experiment_key)
        .execute(&db)
        .await
        .expect("point the step at the experiment");

    // A REAL send selects and persists a variant.
    let outcome =
        common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");
    let variant: String =
        sqlx::query_scalar("SELECT variant FROM sales_step_executions WHERE id = $1")
            .bind(step_execution_id)
            .fetch_one(&db)
            .await
            .expect("the persisted variant");
    let linked_experiment: Option<Uuid> =
        sqlx::query_scalar("SELECT experiment_id FROM sales_enrollments WHERE id = $1")
            .bind(enrollment_id)
            .fetch_one(&db)
            .await
            .expect("the enrollment's experiment link");
    assert!(
        variant == "a" || variant == "b",
        "selected variant: {variant}"
    );
    assert_eq!(linked_experiment, Some(experiment_id));

    let read_arm = |variant: String| {
        let db = db.clone();
        async move {
            sqlx::query_as::<_, (f64, f64, i64, i64, i64)>(
                "SELECT alpha, beta, trials, successes, contacts \
                 FROM sales_experiment_arms WHERE experiment_id = $1 AND variant = $2",
            )
            .bind(experiment_id)
            .bind(variant)
            .fetch_one(&db)
            .await
            .expect("read arm")
        }
    };
    let before = read_arm(variant.clone()).await;

    // A positive business outcome lands in the canonical ledger.
    let outcome_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_outcomes \
             (id, tenant_id, account_id, contact_id, enrollment_id, step_execution_id, \
              outcome, value_eur, occurred_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'positive_reply', 0, NOW())",
    )
    .bind(outcome_id)
    .bind(&tenant_id)
    .bind(seq.account_id)
    .bind(seq.contact_id)
    .bind(enrollment_id)
    .bind(step_execution_id)
    .execute(&db)
    .await
    .expect("insert outcome");

    let projector = OutcomeProjector::new(db.clone(), "gate10-projector");
    let report = projector
        .tick(&ProjectorConfig::default())
        .await
        .expect("projector tick");
    assert!(
        report.rewards.recorded >= 1,
        "the projector must hand the outcome to the reward ledger: {report:?}"
    );

    let after = read_arm(variant.clone()).await;
    assert_eq!(
        after.0,
        before.0 + 0.5,
        "one positive_reply must add its reward to alpha exactly once"
    );
    assert_eq!(
        after.1, before.1,
        "beta must not move for a positive reward"
    );
    assert_eq!(after.2, before.2 + 1, "one informative trial");
    assert_eq!(after.3, before.3 + 1, "one success");
    assert_eq!(after.4, before.4 + 1, "one attributed contact");
    let processed: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT reward_processed_at FROM sales_outcomes WHERE id = $1")
            .bind(outcome_id)
            .fetch_one(&db)
            .await
            .expect("read claim marker");
    assert!(processed.is_some(), "the outcome must be claimed");

    // Replay 1: the reward ledger itself, same logical outcome key
    // (the projector builds `sales-outcome:{outcomes.id}`).
    let outcome_key = format!(
        "{}{}",
        sales_autopilot::outcome_projector::OUTCOME_KEY_PREFIX,
        outcome_id
    );
    sales_autopilot::experiments::record_reward(
        &db,
        &tenant_id,
        experiment_id,
        &variant,
        sales_autopilot::experiments::RewardKind::PositiveReply,
        &outcome_key,
        0.0,
    )
    .await
    .expect("the replay is accepted idempotently");
    assert_eq!(
        read_arm(variant.clone()).await,
        after,
        "replaying the same logical outcome through record_reward must not move the posterior"
    );

    // Replay 2: re-open the claim and replay it through the PROJECTOR.
    sqlx::query("UPDATE sales_outcomes SET reward_processed_at = NULL WHERE id = $1")
        .bind(outcome_id)
        .execute(&db)
        .await
        .expect("re-open the claim");
    let replay = projector
        .tick(&ProjectorConfig::default())
        .await
        .expect("replay tick");
    assert!(replay.rewards.recorded >= 1);
    assert_eq!(
        read_arm(variant.clone()).await,
        after,
        "a replayed outcome through the projector must leave the posterior unchanged"
    );

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Gate 11 — sender-health loop
// ---------------------------------------------------------------------------

/// Gate 11: "Hard-bounce events cross the threshold → the sender is paused and
/// the NEXT decision is denied."
///
/// Drives `sender_health::record_event`, `sender_health::gate` and
/// `decision_engine::decide`.
#[tokio::test]
async fn gate_11_bounce_breaker_pauses_the_sender_and_denies_the_next_decision() {
    let Some((db, tenant_id, seq, _dispatcher)) = fixture(
        "gate11_sender_health",
        common::SequenceFixtureOptions::default(),
    )
    .await
    else {
        return;
    };
    let sender_id = seq.sender_id.expect("fixture seeds a sender");

    // Sanity: before the event stream, this sender passes the gate.
    sales_autopilot::sender_health::gate(&db, &tenant_id, sender_id)
        .await
        .expect("a healthy fixture sender passes the gate");

    // 60 sends: 4 hard bounces (6.67% > the 5% pause threshold) + 56 good.
    let thresholds = sales_autopilot::sender_health::HealthThresholds::default();
    let mut assessment = None;
    for index in 0..60 {
        let event = if index < 4 {
            sales_autopilot::sender_health::SenderHealthEvent::HardBounce
        } else {
            sales_autopilot::sender_health::SenderHealthEvent::Delivered
        };
        assessment = Some(
            sales_autopilot::sender_health::record_event(
                &db,
                &tenant_id,
                sender_id,
                event,
                &thresholds,
            )
            .await
            .expect("record sender event"),
        );
    }
    let assessment = assessment.expect("events recorded");
    assert!(
        matches!(assessment.state.as_str(), "paused" | "quarantined"),
        "the hard-bounce rate must trip the breaker, got {:?}: {:?}",
        assessment.state,
        assessment.reasons
    );
    assert!(
        assessment.health_score < 1.0,
        "the breaker must degrade the health score, got {}",
        assessment.health_score
    );
    let identity_status: String =
        sqlx::query_scalar("SELECT status FROM sales_sender_identities WHERE id = $1")
            .bind(sender_id)
            .fetch_one(&db)
            .await
            .expect("identity status");
    assert!(
        matches!(identity_status.as_str(), "paused" | "quarantined"),
        "the breaker must be mirrored onto the identity, got {identity_status}"
    );
    assert!(
        sales_autopilot::sender_health::gate(&db, &tenant_id, sender_id)
            .await
            .is_err(),
        "the pre-send gate must now refuse"
    );

    // The NEXT decision selecting this sender is denied.
    let outcome = decision_engine::decide(
        &db,
        DecisionContext {
            tenant_id: tenant_id.clone(),
            account_id: Some(seq.account_id),
            contact_id: Some(seq.contact_id),
            contact_point_id: Some(seq.contact_point_id),
            enrollment_id: seq.enrollment_id,
            action: DecisionAction::Contact,
            score: zero_score(),
            expected_value_eur: 100.0,
            confidence: 0.8,
            evidence_ids: Vec::new(),
            selected_offer: None,
            selected_sequence: Some(seq.version_id.to_string()),
            selected_variant: Some("default".to_string()),
            selected_sender: Some(sender_id),
            model_version: Some("release-gate-v1".to_string()),
            policy: Some(allowed_policy_input(&seq)),
            rationale: "gate 11".to_string(),
            execute_after: None,
        },
    )
    .await
    .expect("the decision engine runs");
    assert_eq!(
        outcome.enforcement,
        Enforcement::Denied,
        "a paused sender must deny the next decision: {:?}",
        outcome.block_reasons
    );
    assert!(
        outcome
            .block_reasons
            .iter()
            .any(|reason| reason.contains("sender_health_denied")),
        "the denial must name the sender-health gate, got {:?}",
        outcome.block_reasons
    );

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Gate 18 — opaque unsubscribe token
// ---------------------------------------------------------------------------

/// Gate 18: "The delivered unsubscribe token carries neither the recipient nor
/// the tenant, nor any hex/base64 representation of either."
///
/// Strengthens the in-module tests
/// (`sales_autopilot::dispatcher::tests::token_is_opaque_no_plaintext_pii`,
/// `...::v2_token_url_carries_no_recipient_tenant_or_hex_payload`) by driving
/// a REAL send and inspecting the token the dispatcher actually emitted, and
/// by covering base64/URL-safe encodings those tests do not.
#[tokio::test]
async fn gate_18_delivered_unsubscribe_token_carries_no_identity_encoding() {
    let Some((db, tenant_id, seq, dispatcher)) = fixture(
        "gate18_opaque_token",
        common::SequenceFixtureOptions::default(),
    )
    .await
    else {
        return;
    };
    let step_execution_id = seq.step_execution_id.expect("fixture enrolls");

    let outcome =
        common::run_send_step(&db, dispatcher.clone(), &tenant_id, step_execution_id).await;
    assert!(matches!(outcome, ActionOutcome::Succeeded), "{outcome:?}");

    let headers: serde_json::Value =
        sqlx::query_scalar("SELECT headers FROM email_queue WHERE tenant_id = $1 LIMIT 1")
            .bind(&tenant_id)
            .fetch_one(&db)
            .await
            .expect("the emitted headers");
    let link = headers
        .get("List-Unsubscribe")
        .and_then(|value| value.as_str())
        .expect("List-Unsubscribe header");
    assert!(
        link.starts_with('<') && link.ends_with('>'),
        "link shape: {link}"
    );
    let token = link
        .trim_start_matches('<')
        .trim_end_matches('>')
        .rsplit('/')
        .next()
        .expect("token segment");

    use base64::Engine as _;
    let email = seq.email.to_ascii_lowercase();
    let tenant_lower = tenant_id.to_ascii_lowercase();
    let email_local = email.split('@').next().unwrap_or_default().to_string();
    let encodings = [
        ("plain recipient", email.clone()),
        ("plain tenant", tenant_lower.clone()),
        ("recipient local part", email_local),
        ("recipient hex", hex_encode(email.as_bytes())),
        ("recipient HEX", hex_encode(email.as_bytes()).to_uppercase()),
        ("tenant hex", hex_encode(tenant_lower.as_bytes())),
        (
            "recipient base64",
            base64::engine::general_purpose::STANDARD.encode(email.as_bytes()),
        ),
        (
            "recipient base64url",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(email.as_bytes()),
        ),
        (
            "tenant base64",
            base64::engine::general_purpose::STANDARD.encode(tenant_lower.as_bytes()),
        ),
        (
            "tenant base64url",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tenant_lower.as_bytes()),
        ),
    ];
    for (label, encoded) in encodings {
        assert!(
            !token.contains(&encoded),
            "the emitted unsubscribe token must not carry the {label}"
        );
    }

    common::cleanup_tenant(&db, &tenant_id).await;
}

// ---------------------------------------------------------------------------
// Gate 20 — lead indexes
// ---------------------------------------------------------------------------

/// Gate 20: "`pg_indexes` confirms the unique email index and the GIN search
/// index."
///
/// SCHEMA/DEPLOY-CONTRACT GATE (not a call-path gate): migration 203 owns
/// these indexes, and a deploy that predates/omits it must go red here. The
/// final probe proves the unique index actually enforces, not just exists.
#[tokio::test]
async fn gate_20_sales_leads_unique_and_gin_indexes_are_schema_owned() {
    let Some(db) = common::test_pool("gate20_lead_indexes").await else {
        return;
    };

    let defs: Vec<(String, String)> = sqlx::query_as(
        "SELECT indexname, indexdef FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'sales_leads' \
           AND indexname IN ('idx_sales_leads_tenant_email', 'idx_sales_leads_fts_gin')",
    )
    .fetch_all(&db)
    .await
    .expect("read pg_indexes");

    let unique = defs
        .iter()
        .find(|(name, _)| name == "idx_sales_leads_tenant_email")
        .map(|(_, def)| def.clone())
        .expect("migration 203 must create idx_sales_leads_tenant_email");
    assert!(
        unique.contains("UNIQUE"),
        "the duplicate check depends on uniqueness: {unique}"
    );
    assert!(
        unique.contains("lower(contact_email)"),
        "the duplicate key must be (tenant_id, lower(contact_email)): {unique}"
    );

    let gin = defs
        .iter()
        .find(|(name, _)| name == "idx_sales_leads_fts_gin")
        .map(|(_, def)| def.clone())
        .expect("migration 203 must create idx_sales_leads_fts_gin");
    assert!(
        gin.contains("USING gin"),
        "the search path requires a GIN index: {gin}"
    );
    assert!(
        gin.contains("to_tsvector"),
        "the GIN index must cover the search expression: {gin}"
    );

    // Enforcement probe: the unique index must actually reject a second lead
    // for the same (tenant, lower(email)) pair.
    let suffix = Uuid::new_v4().simple().to_string();
    let lead_id = format!("gate20-a-{suffix}");
    let email = format!("gate20-{suffix}@example.com");
    sqlx::query(
        "INSERT INTO sales_leads (id, tenant_id, company_name, domain, status, contact_email) \
         VALUES ($1, 'system', 'Gate 20', 'gate20.example', 'new', $2)",
    )
    .bind(&lead_id)
    .bind(&email)
    .execute(&db)
    .await
    .expect("first lead insert");
    let duplicate = sqlx::query(
        "INSERT INTO sales_leads (id, tenant_id, company_name, domain, status, contact_email) \
         VALUES ($1, 'system', 'Gate 20', 'gate20.example', 'new', $2)",
    )
    .bind(format!("gate20-b-{suffix}"))
    .bind(email.to_uppercase())
    .execute(&db)
    .await;
    assert!(
        duplicate.is_err(),
        "the unique index must reject a duplicate (tenant, lower(email)) pair"
    );
    let _ = sqlx::query("DELETE FROM sales_leads WHERE id = $1 OR id = $2")
        .bind(&lead_id)
        .bind(format!("gate20-b-{suffix}"))
        .execute(&db)
        .await;
}

// ---------------------------------------------------------------------------
// Deploy-contract gates (outside item 27's list, retained)
// ---------------------------------------------------------------------------

/// Deploy contract: re-applying the canonical migration chain is an idempotent
/// no-op and never drops the sales surface.
#[tokio::test]
async fn deploy_contract_canonical_migration_is_idempotent_when_reapplied() {
    let Some(db) = common::test_pool("migration_idempotent").await else {
        return;
    };

    migrator::apply_migrations(&db)
        .await
        .expect("re-applying the canonical chain must succeed (idempotent)");

    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname='public' AND c.relkind='r' \
           AND c.relname IN ('sales_actions','sales_enrollments','sales_decisions','sales_outcomes')",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        tables, 4,
        "re-applying the chain must not drop the sales tables"
    );
}

/// Deploy contract: the schema guard refuses a database missing the sales
/// schema instead of silently serving it.
#[tokio::test]
async fn deploy_contract_schema_guard_refuses_a_drifted_database() {
    let Some(db) = common::test_pool("schema_guard").await else {
        return;
    };

    // A canonically migrated database passes the guard.
    sales_autopilot::schema::verify(&db)
        .await
        .expect("a canonically migrated database must pass the schema guard");

    // An empty database — as a deployment would be before the migrator runs —
    // must be refused, and the error must name what is missing.
    let base = std::env::var("SALES_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("TEST_DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://localhost/unused".to_string());
    let Some((server, _)) = base.rsplit_once('/') else {
        return;
    };
    let empty_name = format!("apexmail_empty_guard_{}", Uuid::new_v4().simple());
    let admin = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&base)
        .await
    {
        Ok(pool) => pool,
        Err(_) => return,
    };
    if sqlx::query(&format!("CREATE DATABASE \"{empty_name}\""))
        .execute(&admin)
        .await
        .is_err()
    {
        return;
    }

    let empty = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{server}/{empty_name}"))
        .await
        .expect("the throwaway database must be reachable");

    let verdict = sales_autopilot::schema::verify(&empty).await;
    match verdict {
        Err(sales_autopilot::types::SalesError::SchemaIncompatible(message)) => {
            assert!(
                message.contains("sales_actions"),
                "the refusal must name a missing table, got: {message}"
            );
        }
        Ok(()) => panic!("an empty database must NOT pass the schema guard"),
        Err(other) => panic!("expected SchemaIncompatible, got {other:?}"),
    }

    empty.close().await;
    let _ = sqlx::query(&format!(
        "DROP DATABASE IF EXISTS \"{empty_name}\" WITH (FORCE)"
    ))
    .execute(&admin)
    .await;
    admin.close().await;
}
