//! Live-database integration tests for the §8/§7/§11/§19/§38 completion work.
//!
//! Every test is `#[ignore]`d because it needs a real migrated Postgres.
//! Run with:
//!
//! ```sh
//! TEST_DATABASE_URL=postgresql://apexmail:...@localhost:5432/apexmail \
//!   cargo test -p sales-autopilot --test sales_v2_completion -- --ignored
//! ```
//!
//! The suite soft-skips (printing `SKIP`) when neither
//! `SALES_TEST_DATABASE_URL` nor `TEST_DATABASE_URL` is set; a configured but
//! unreachable database is a hard failure (see tests/common/mod.rs).

mod common;

use chrono::{DateTime, Duration, Utc};
use sales_autopilot::account_coordination::{
    active_contact_count, request_contact_slot, request_contact_slot_in_tx, AccountPolicy,
    CoordinationVerdict,
};
use sales_autopilot::attribution::{
    attribute_revenue, click_metrics, record_outcome, AttributionWindow, OutcomeKind, OutcomeRecord,
};
use sales_autopilot::scoring::{self, latest_for_account, persist, ScoreFeatures};
use sales_autopilot::signals::{active_signals, email_stack, record_signal, SignalType};
use sqlx::PgPool;
use uuid::Uuid;

fn unique_suffix() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_string()
}

async fn insert_account(
    pool: &PgPool,
    tenant_id: &str,
    max_active_contacts: i16,
    multi_thread_allowed: bool,
    negative_reply_cooldown_hours: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    let domain = format!("acct-{}.example.com", unique_suffix());
    sqlx::query(
        "INSERT INTO sales_accounts (
            id, tenant_id, company, domain, country, country_confidence,
            eea_relevance, icp_segment, lifecycle, max_active_contacts,
            multi_thread_allowed, negative_reply_cooldown_hours
         ) VALUES ($1, $2, $3, $4, 'DE', 0.9, 'in_scope', 'saas', 'discovered', $5, $6, $7)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(format!("Fixture Co {id}"))
    .bind(&domain)
    .bind(max_active_contacts)
    .bind(multi_thread_allowed)
    .bind(negative_reply_cooldown_hours)
    .execute(pool)
    .await
    .expect("insert sales_accounts fixture");
    id
}

async fn insert_contact(
    pool: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    persona: Option<&str>,
    job_title: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_contacts (
            id, tenant_id, account_id, full_name, job_title, department,
            seniority, persona, country, lifecycle
         ) VALUES ($1, $2, $3, $4, $5, 'engineering', 'vp', $6, 'DE', 'active')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(account_id)
    .bind(format!("Person {id}"))
    .bind(job_title)
    .bind(persona)
    .execute(pool)
    .await
    .expect("insert sales_contacts fixture");
    id
}

struct SequenceChain {
    version_id: Uuid,
    step_id: Uuid,
}

async fn insert_sequence_chain(pool: &PgPool, tenant_id: &str, name: &str) -> SequenceChain {
    let sequence_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let step_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_sequences (id, tenant_id, name, status) VALUES ($1, $2, $3, 'active')",
    )
    .bind(sequence_id)
    .bind(tenant_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("insert sales_sequences fixture");
    sqlx::query(
        "INSERT INTO sales_sequence_versions (id, tenant_id, sequence_id, version, status, locale)
         VALUES ($1, $2, $3, 1, 'active', 'en')",
    )
    .bind(version_id)
    .bind(tenant_id)
    .bind(sequence_id)
    .execute(pool)
    .await
    .expect("insert sales_sequence_versions fixture");
    sqlx::query(
        "INSERT INTO sales_sequence_steps (id, tenant_id, version_id, step_index, kind)
         VALUES ($1, $2, $3, 0, 'email')",
    )
    .bind(step_id)
    .bind(tenant_id)
    .bind(version_id)
    .execute(pool)
    .await
    .expect("insert sales_sequence_steps fixture");
    SequenceChain {
        version_id,
        step_id,
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_enrollment(
    pool: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    contact_id: Uuid,
    version_id: Uuid,
    state: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_enrollments (
            id, tenant_id, sequence_version_id, account_id, contact_id, state
         ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(version_id)
    .bind(account_id)
    .bind(contact_id)
    .bind(state)
    .execute(pool)
    .await
    .expect("insert sales_enrollments fixture");
    id
}

async fn insert_step_execution(
    pool: &PgPool,
    tenant_id: &str,
    enrollment_id: Uuid,
    chain: &SequenceChain,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_step_executions (
            id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id,
            step_index, state, idempotency_key, executed_at
         ) VALUES ($1, $2, $3, $4, $5, 0, 'sent', $6, NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(enrollment_id)
    .bind(chain.version_id)
    .bind(chain.step_id)
    .bind(format!("test-{}", unique_suffix()))
    .execute(pool)
    .await
    .expect("insert sales_step_executions fixture");
    id
}

async fn insert_reply_classification(
    pool: &PgPool,
    tenant_id: &str,
    enrollment_id: Uuid,
    contact_id: Uuid,
    disposition: &str,
) {
    sqlx::query(
        "INSERT INTO sales_reply_classifications (
            id, tenant_id, enrollment_id, contact_id, disposition, classifier, confidence
         ) VALUES ($1, $2, $3, $4, $5, 'deterministic', 0.9)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(enrollment_id)
    .bind(contact_id)
    .bind(disposition)
    .execute(pool)
    .await
    .expect("insert sales_reply_classifications fixture");
}

// ---------------------------------------------------------------------------
// §19 — outcome idempotency and revenue attribution
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn outcome_replay_is_idempotent_and_revenue_is_not_double_counted() {
    let Some(pool) = common::test_pool("outcome_replay").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "outcome-replay").await;
    let account = insert_account(&pool, &tenant, 2, true, 0).await;
    let contact = insert_contact(&pool, &tenant, account, Some("CTO"), "CTO").await;
    let chain = insert_sequence_chain(&pool, &tenant, "Replay sequence").await;
    let enrollment =
        insert_enrollment(&pool, &tenant, account, contact, chain.version_id, "active").await;
    let step = insert_step_execution(&pool, &tenant, enrollment, &chain).await;

    let mut record = OutcomeRecord::new(OutcomeKind::PaidSubscription);
    record.account_id = Some(account);
    record.contact_id = Some(contact);
    record.enrollment_id = Some(enrollment);
    record.step_execution_id = Some(step);
    record.discovery_source = Some("live_test_source".into());
    record.offer = Some("deliverability_audit".into());
    record.value_eur = 500.0;
    record.provider = Some("stripe".into());

    let first_id = record_outcome(&pool, &tenant, &record)
        .await
        .expect("first write");
    let replay_id = record_outcome(&pool, &tenant, &record)
        .await
        .expect("replay");
    assert_eq!(
        first_id, replay_id,
        "replaying (tenant, outcome, step_execution_id) must return the same row"
    );

    let (rows, total): (i64, f64) = sqlx::query_as(
        "SELECT COUNT(*)::bigint, COALESCE(SUM(value_eur), 0)::float8 FROM sales_outcomes
         WHERE tenant_id = $1 AND outcome = 'paid_subscription' AND step_execution_id = $2",
    )
    .bind(&tenant)
    .bind(step)
    .fetch_one(&pool)
    .await
    .expect("count outcomes");
    assert_eq!(rows, 1, "one logical outcome must produce exactly one row");
    assert!(
        (total - 500.0).abs() < 1e-9,
        "revenue must not double-count"
    );

    // The report joins the whole chain and sees the revenue exactly once.
    let window = AttributionWindow::new(
        Utc::now() - Duration::hours(1),
        Utc::now() + Duration::hours(1),
    );
    let report = attribute_revenue(&pool, &tenant, window)
        .await
        .expect("attribute_revenue");
    assert_eq!(report.revenue_created_eur, Some(500.0));
    assert_eq!(report.mrr_created_eur, None, "no retained_mrr recorded");
    assert_eq!(report.paying_customers, 1);
    assert_eq!(report.discovered_accounts, 1);
    assert_eq!(report.contacted_contacts, 1);
    assert_eq!(report.qualified_reply_rate, Some(1.0));

    let breakdown = report
        .by_discovery_source
        .iter()
        .find(|row| row.discovery_source.as_deref() == Some("live_test_source"))
        .expect("breakdown walks sales_outcomes -> step_executions -> enrollments -> sequences");
    assert_eq!(breakdown.offer.as_deref(), Some("deliverability_audit"));
    assert_eq!(breakdown.sequence_name.as_deref(), Some("Replay sequence"));
    assert_eq!(breakdown.icp_segment.as_deref(), Some("saas"));
    assert!((breakdown.revenue_eur - 500.0).abs() < 1e-9);

    // Clicks stay out of the headline report and behind the secondary accessor.
    let clicks = click_metrics(&pool, &tenant, window)
        .await
        .expect("click metrics");
    assert_eq!(clicks.clicks, 0);
    assert_eq!(clicks.click_rate, None, "zero denominator → None, not 0");
}

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn attribution_zero_denominator_is_none_not_zero_or_infinity() {
    let Some(pool) = common::test_pool("attribution_zero").await else {
        return;
    };
    // A tenant with no accounts, no outcomes and no costs at all.
    let tenant = common::insert_test_tenant(&pool, "attribution-zero").await;
    let window = AttributionWindow::new(
        Utc::now() - Duration::hours(1),
        Utc::now() + Duration::hours(1),
    );
    let report = attribute_revenue(&pool, &tenant, window)
        .await
        .expect("attribute_revenue on empty tenant");
    assert_eq!(report.discovered_accounts, 0);
    assert_eq!(report.contacted_contacts, 0);
    assert_eq!(report.revenue_created_eur, None);
    assert_eq!(report.mrr_created_eur, None);
    assert_eq!(report.pipeline_created_eur, None);
    assert_eq!(report.revenue_per_1000_discovered_eur, None);
    assert_eq!(report.revenue_per_1000_contacted_eur, None);
    assert_eq!(report.qualified_reply_rate, None);
    assert_eq!(report.meeting_conversion, None);
    assert_eq!(report.cac_eur, None);
    assert_eq!(report.total_cost_eur, None);
    assert_eq!(report.gross_profit_acquired_eur, None);
    assert!(report.by_discovery_source.is_empty());

    // Hostile windows: zero length and a century-wide span.
    let zero = AttributionWindow::new(Utc::now(), Utc::now());
    let zero_report = attribute_revenue(&pool, &tenant, zero)
        .await
        .expect("zero window");
    assert_eq!(zero_report.discovered_accounts, 0);
    assert_eq!(zero_report.revenue_per_1000_discovered_eur, None);

    let century = AttributionWindow::new(
        Utc::now() - Duration::days(36_500),
        Utc::now() + Duration::days(36_500),
    );
    let century_report = attribute_revenue(&pool, &tenant, century)
        .await
        .expect("century window");
    assert!(century_report.window.duration_days() > 36_000.0);
    assert_eq!(century_report.revenue_per_1000_discovered_eur, None);
}

// ---------------------------------------------------------------------------
// §38 — coordination race
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn coordination_race_at_cap_never_exceeds_budget() {
    let Some(pool) = common::test_pool("coordination_race").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "coord-race").await;
    // Budget of 2, multi-threading permitted, no cooldown.
    let account = insert_account(&pool, &tenant, 2, true, 0).await;
    let incumbent = insert_contact(&pool, &tenant, account, Some("CTO"), "CTO").await;
    let challenger_a = insert_contact(&pool, &tenant, account, Some("VP"), "VP Engineering").await;
    let challenger_b = insert_contact(&pool, &tenant, account, Some("VP"), "VP Engineering").await;
    let chain = insert_sequence_chain(&pool, &tenant, "Race sequence").await;
    // One slot already occupied: exactly one of the two challengers may win.
    insert_enrollment(
        &pool,
        &tenant,
        account,
        incumbent,
        chain.version_id,
        "active",
    )
    .await;

    let version_id = chain.version_id;
    let mut handles = Vec::new();
    for contact in [challenger_a, challenger_b] {
        let pool = pool.clone();
        let tenant = tenant.clone();
        handles.push(tokio::spawn(async move {
            let mut tx = pool.begin().await.expect("begin");
            let verdict =
                request_contact_slot_in_tx(&mut tx, &tenant, account, contact, Utc::now(), false)
                    .await
                    .expect("slot decision");
            if verdict.is_allowed() {
                sqlx::query(
                    "INSERT INTO sales_enrollments (
                        id, tenant_id, sequence_version_id, account_id, contact_id, state
                     ) VALUES ($1, $2, $3, $4, $5, 'active')",
                )
                .bind(Uuid::new_v4())
                .bind(&tenant)
                .bind(version_id)
                .bind(account)
                .bind(contact)
                .execute(&mut *tx)
                .await
                .expect("reserve slot");
                tx.commit().await.expect("commit");
                true
            } else {
                tx.rollback().await.expect("rollback");
                false
            }
        }));
    }

    let results = futures::future::join_all(handles).await;
    let allowed = results
        .iter()
        .filter(|result| matches!(result, Ok(true)))
        .count();
    assert_eq!(
        allowed, 1,
        "at the cap, exactly one concurrent request must win the last slot"
    );
    let final_count = active_contact_count(&pool, &tenant, account)
        .await
        .expect("active count");
    assert_eq!(final_count, 2, "account cap must hold under concurrency");
}

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn coordination_rules_against_live_state() {
    let Some(pool) = common::test_pool("coordination_rules").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "coord-rules").await;
    let account = insert_account(&pool, &tenant, 3, true, 24).await;
    let first = insert_contact(&pool, &tenant, account, Some("CTO"), "CTO").await;
    let second = insert_contact(&pool, &tenant, account, Some("VP"), "VP Engineering").await;
    let chain = insert_sequence_chain(&pool, &tenant, "Rules sequence").await;
    let enrollment =
        insert_enrollment(&pool, &tenant, account, first, chain.version_id, "active").await;

    // Free slot and no negative history: allowed.
    let verdict = request_contact_slot(&pool, &tenant, account, second, Utc::now())
        .await
        .expect("slot request");
    assert!(verdict.is_allowed(), "expected Allowed, got {verdict:?}");

    // A negative reply starts the 24h cooldown.
    insert_reply_classification(&pool, &tenant, enrollment, first, "not_interested").await;
    let verdict = request_contact_slot(&pool, &tenant, account, second, Utc::now())
        .await
        .expect("slot request after negative reply");
    match verdict {
        CoordinationVerdict::Deferred { until } => {
            assert!(until > Utc::now(), "cooldown must end in the future");
        }
        other => panic!("expected Deferred, got {other:?}"),
    }

    // A strong objection stops the whole account even with a free slot.
    insert_reply_classification(&pool, &tenant, enrollment, first, "unsubscribe").await;
    let verdict = request_contact_slot(&pool, &tenant, account, second, Utc::now())
        .await
        .expect("slot request after strong objection");
    match verdict {
        CoordinationVerdict::Denied(reason) => {
            assert!(reason.contains("strong objection"), "reason: {reason}");
        }
        other => panic!("expected Denied, got {other:?}"),
    }

    let count = active_contact_count(&pool, &tenant, account)
        .await
        .expect("active count");
    assert_eq!(count, 1);
}

// ---------------------------------------------------------------------------
// §8 — score persistence
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn score_persist_and_latest_roundtrip() {
    let Some(pool) = common::test_pool("score_persist").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "score-persist").await;
    let account = insert_account(&pool, &tenant, 2, false, 0).await;
    let contact = insert_contact(&pool, &tenant, account, Some("VP"), "VP Engineering").await;

    let mut features = ScoreFeatures::default();
    features.segment_match = scoring::SegmentMatch::Strong;
    features.employees = Some(220);
    features.industry = Some("B2B SaaS".into());
    features.intent_signals = vec![sales_autopilot::signals::SignalObservation {
        signal_type: SignalType::APEXMAIL_MIGRATION_PAGE_VISIT.into(),
        strength: 0.9,
        observed_at: Utc::now(),
    }];
    features.legal = sales_autopilot::types::ContactDecision::Allowed;
    features.economics.expected_ltv_contribution_eur = 25_000.0;

    let opportunity = scoring::score(&features);
    let stored_id = persist(&pool, &tenant, account, Some(contact), &opportunity)
        .await
        .expect("persist score");

    let latest = latest_for_account(&pool, &tenant, account)
        .await
        .expect("latest score")
        .expect("a stored score");
    assert_eq!(latest.scoring_version, scoring::SCORING_VERSION);
    assert_eq!(latest.total, opportunity.total);
    assert_eq!(latest.intent, opportunity.intent);
    assert_eq!(latest.reason_codes, opportunity.reason_codes);
    assert!((latest.expected_value_eur - opportunity.expected_value_eur).abs() < 1e-4);

    // Every column was written: read the raw row back for the dimensions.
    let (total, version, codes): (f64, String, serde_json::Value) = sqlx::query_as(
        "SELECT total, scoring_version, reason_codes FROM sales_scores WHERE id = $1",
    )
    .bind(stored_id)
    .fetch_one(&pool)
    .await
    .expect("raw score row");
    assert!((total - f64::from(opportunity.total)).abs() < 1e-6);
    assert_eq!(version, scoring::SCORING_VERSION);
    assert!(codes.as_array().is_some_and(|codes| !codes.is_empty()));
}

// ---------------------------------------------------------------------------
// §7/§11 — signals and evidence
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn signals_respect_expiry_and_link_evidence() {
    let Some(pool) = common::test_pool("signals").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "signals").await;
    let account = insert_account(&pool, &tenant, 2, false, 0).await;

    // Evidence first, so the signal can link to it.
    let evidence_row = email_stack::Evidence::new(
        "company_may_use_sendgrid",
        email_stack::CONFIDENCE_WEAK_HINT,
        email_stack::EvidenceSourceKind::DnsObservation,
        Utc::now(),
    )
    .with_source_ref("spf include:sendgrid.net");
    let evidence_id =
        email_stack::persist_evidence(&pool, &tenant, Some(account), None, &evidence_row)
            .await
            .expect("persist evidence");

    let active_id = record_signal(
        &pool,
        &tenant,
        account,
        SignalType::EMAIL_STACK_CHANGE,
        0.7,
        Some(evidence_id),
        serde_json::json!({"change": "dkim_added"}),
        Some(Utc::now() + Duration::hours(1)),
    )
    .await
    .expect("record active signal");

    let expired_id = record_signal(
        &pool,
        &tenant,
        account,
        SignalType::FUNDING,
        0.9,
        None,
        serde_json::json!({}),
        Some(Utc::now() - Duration::hours(1)),
    )
    .await
    .expect("record expired signal");
    assert_ne!(active_id, expired_id);

    let live = active_signals(&pool, &tenant, account, Utc::now())
        .await
        .expect("active signals");
    assert_eq!(live.len(), 1, "expired signal must be filtered: {live:?}");
    assert_eq!(live[0].id, active_id);
    assert_eq!(live[0].signal_type, SignalType::EMAIL_STACK_CHANGE);
    assert_eq!(live[0].evidence_id, Some(evidence_id));
    assert!(live[0].urgency(Utc::now()) > 0.0);

    // Hostile signal strength is rejected before touching the database.
    let error = record_signal(
        &pool,
        &tenant,
        account,
        SignalType::FUNDING,
        f64::NAN,
        None,
        serde_json::json!({}),
        None,
    )
    .await
    .expect_err("NaN strength must be rejected");
    assert!(matches!(
        error,
        sales_autopilot::types::SalesError::InvalidInput(_)
    ));
}

// ---------------------------------------------------------------------------
// §8 — pure scoring module is exported with the frozen types
// ---------------------------------------------------------------------------

#[test]
fn module_public_api_smoke() {
    // Compile-time surface check for the frozen `OpportunityScore` shape.
    let opportunity: sales_autopilot::types::OpportunityScore =
        scoring::score(&ScoreFeatures::default());
    let _: f32 = opportunity.total;
    let _: f64 = opportunity.expected_value_eur;
    let _: &Vec<String> = &opportunity.reason_codes;
    let _: &str = &opportunity.scoring_version;

    let window = AttributionWindow::new(Utc::now(), Utc::now() + Duration::days(1));
    assert!(!window.is_empty());

    let policy = AccountPolicy::default();
    assert!(policy.max_active_contacts > 0);
    let verdict =
        sales_autopilot::account_coordination::decide(&policy, 0, None, false, false, Utc::now());
    assert!(verdict.is_allowed());

    let kinds = [
        OutcomeKind::Delivered,
        OutcomeKind::Open,
        OutcomeKind::Click,
        OutcomeKind::Reply,
        OutcomeKind::PositiveReply,
        OutcomeKind::MeetingBooked,
        OutcomeKind::MeetingAttended,
        OutcomeKind::Trial,
        OutcomeKind::PaidSubscription,
        OutcomeKind::RetainedMrr,
        OutcomeKind::Bounce,
        OutcomeKind::Complaint,
        OutcomeKind::Unsubscribe,
    ];
    assert_eq!(kinds.len(), 13);

    let observed: DateTime<Utc> = Utc::now();
    let signal = sales_autopilot::signals::SignalObservation {
        signal_type: SignalType::TRIAL_SIGNUP.into(),
        strength: 1.0,
        observed_at: observed,
    };
    assert_eq!(
        sales_autopilot::signals::combined_urgency(&[signal], observed),
        1.0
    );
}
