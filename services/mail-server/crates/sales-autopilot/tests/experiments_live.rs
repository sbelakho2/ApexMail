//! Live-database integration tests for the §17/§18/§28/§35/§36/§37/§12 work.
//!
//! Every test is `#[ignore]`d because it needs a real canonically migrated
//! Postgres. Run with:
//!
//! ```sh
//! TEST_DATABASE_URL=postgresql://apexmail:...@localhost:5432/apexmail \
//!   cargo test -p sales-autopilot --test experiments_live -- --ignored
//! ```
//!
//! The suite soft-skips (printing `SKIP`) when neither
//! `SALES_TEST_DATABASE_URL` nor `TEST_DATABASE_URL` is set; a configured but
//! unreachable database is a hard failure (see tests/common/mod.rs). The
//! database is provisioned through the real production migrator
//! (`migrator::test_support::shared_canonical_db`, audit F01).

mod common;

use std::sync::Arc;

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sales_autopilot::actions::{ActionHandler, ActionOutcome};
use sales_autopilot::attribution::{OutcomeKind, OutcomeRecord};
use sales_autopilot::dispatcher::ProductionCampaignDispatcher;
use sales_autopilot::experiments::{
    next_best_action, ArmSpec, EmailState, ExperimentContext, ExperimentEngine, NextActionInput,
    ReplyState, RewardKind, VariantContext, MIN_CONTEXT_SAMPLES,
};
use sales_autopilot::intelligence::{
    AngleRequest, AngleSelection, DraftRequest, DraftedMessage, IntelligenceError,
    NextActionRequest, ReplyClassification, ReplyRequest, ResearchClaim, ResearchFindings,
    ResearchRequest, SalesIntelligence,
};
use sales_autopilot::research::{ResearchMode, HYPOTHESIS_PREFIX};
use sales_autopilot::scoring;
use sales_autopilot::sequence_worker::SequenceStepHandler;
use sales_autopilot::types::{DecisionAction, SalesError};

fn unique_suffix() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_string()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn insert_account(
    pool: &PgPool,
    tenant_id: &str,
    icp_segment: &str,
    country: &str,
    employees: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    let domain = format!("exp-{}.example.com", unique_suffix());
    sqlx::query(
        "INSERT INTO sales_accounts (
            id, tenant_id, company, domain, country, country_confidence,
            eea_relevance, icp_segment, employees, lifecycle
         ) VALUES ($1, $2, $3, $4, $5, 0.9, 'in_scope', $6, $7, 'discovered')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(format!("Experiment Co {id}"))
    .bind(&domain)
    .bind(country)
    .bind(icp_segment)
    .bind(employees)
    .execute(pool)
    .await
    .expect("insert sales_accounts fixture");
    id
}

async fn insert_contact(pool: &PgPool, tenant_id: &str, account_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_contacts (
            id, tenant_id, account_id, full_name, job_title, department,
            seniority, persona, country, language, lifecycle
         ) VALUES ($1, $2, $3, $4, 'CTO', 'engineering', 'c-level', 'cto', 'DE', 'de', 'active')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(account_id)
    .bind(format!("Person {id}"))
    .execute(pool)
    .await
    .expect("insert sales_contacts fixture");
    id
}

async fn insert_contact_point(pool: &PgPool, tenant_id: &str, contact_id: Uuid, email: &str) {
    sqlx::query(
        "INSERT INTO sales_contact_points (
            id, tenant_id, contact_id, channel, value, normalized_value,
            verification, confidence, source
         ) VALUES ($1, $2, $3, 'email', $4, $4, 'valid', 0.95, 'test')",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(contact_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("insert sales_contact_points fixture");
}

async fn insert_experiment(
    pool: &PgPool,
    tenant_id: &str,
    key: &str,
    budgets: serde_json::Value,
    dimensions: serde_json::Value,
) -> Uuid {
    let engine = ExperimentEngine::new(pool.clone());
    let id = engine
        .ensure_experiment(
            tenant_id,
            key,
            "Integration experiment",
            &serde_json::json!({ "dimensions": dimensions }),
            &budgets,
        )
        .await
        .expect("ensure experiment");
    engine
        .set_status(
            tenant_id,
            id,
            sales_autopilot::experiments::ExperimentStatus::Running,
        )
        .await
        .expect("set running");
    engine
        .ensure_arms(
            tenant_id,
            id,
            &[ArmSpec::control("control"), ArmSpec::new("challenger")],
        )
        .await
        .expect("ensure arms");
    id
}

async fn insert_sequence_chain(
    pool: &PgPool,
    tenant_id: &str,
    name: &str,
    template_id: Option<&str>,
    experiment_key: Option<&str>,
) -> (Uuid, Uuid) {
    let sequence_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let step_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_sequences (id, tenant_id, name, status) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind(sequence_id)
    .bind(tenant_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("insert sales_sequences fixture");
    sqlx::query(
        "INSERT INTO sales_sequence_versions (id, tenant_id, sequence_id, version, status, locale) \
         VALUES ($1, $2, $3, 1, 'active', 'en')",
    )
    .bind(version_id)
    .bind(tenant_id)
    .bind(sequence_id)
    .execute(pool)
    .await
    .expect("insert sales_sequence_versions fixture");
    sqlx::query(
        "INSERT INTO sales_sequence_steps (
            id, tenant_id, version_id, step_index, kind, template_id, experiment_key
         ) VALUES ($1, $2, $3, 0, 'email', $4, $5)",
    )
    .bind(step_id)
    .bind(tenant_id)
    .bind(version_id)
    .bind(template_id)
    .bind(experiment_key)
    .execute(pool)
    .await
    .expect("insert sales_sequence_steps fixture");
    (version_id, step_id)
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
    version_id: Uuid,
    step_id: Uuid,
    state: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_step_executions (
            id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id,
            step_index, state, idempotency_key
         ) VALUES ($1, $2, $3, $4, $5, 0, $6, $7)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(enrollment_id)
    .bind(version_id)
    .bind(step_id)
    .bind(state)
    .bind(format!("inttest-{}", unique_suffix()))
    .execute(pool)
    .await
    .expect("insert sales_step_executions fixture");
    id
}

async fn set_autonomy(pool: &PgPool, tenant_id: &str, mode: &str) {
    sqlx::query(
        "INSERT INTO sales_autonomy_state (tenant_id, mode, kill_switch, updated_at) \
         VALUES ($1, $2, FALSE, NOW()) \
         ON CONFLICT (tenant_id) DO UPDATE SET mode = EXCLUDED.mode, kill_switch = FALSE",
    )
    .bind(tenant_id)
    .bind(mode)
    .execute(pool)
    .await
    .expect("set autonomy state");
}

/// Admission backend that fails every reservation with an infrastructure
/// error (a simulated billing outage before enqueue).
#[derive(Debug)]
struct FailingAdmissionBackend;

#[async_trait::async_trait]
impl billing_service::send_admission::SendAdmissionBackend for FailingAdmissionBackend {
    async fn record_send_usage(
        &self,
        _tenant_id: &str,
        _quantity: i64,
        _event_id: Uuid,
    ) -> Result<billing_service::usage::QuotaRecordResult, billing_service::usage::UsageError> {
        Err(billing_service::usage::UsageError::Audit(
            "simulated billing outage before enqueue".into(),
        ))
    }

    async fn rollback_send_usage(
        &self,
        _tenant_id: &str,
        _quantity: i64,
        _event_id: Uuid,
        _recorded_at: chrono::DateTime<Utc>,
    ) -> Result<(), billing_service::usage::UsageError> {
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

// ---------------------------------------------------------------------------
// §17 — reward ledger idempotency and the ladder
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn reward_ledger_is_idempotent_and_the_ladder_moves_the_posterior_once() {
    let Some(pool) = common::test_pool("reward_ledger").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "reward-ledger").await;
    let experiment = insert_experiment(
        &pool,
        &tenant,
        &format!("exp-{}", unique_suffix()),
        serde_json::json!({}),
        serde_json::json!(["icp_segment"]),
    )
    .await;
    // `sales_experiment_outcomes.outcome_key` is a global primary key and the
    // shared canonical test database survives across processes, so keys must
    // be unique per run.
    let run = unique_suffix();
    let outcome_key = format!("outcome-{run}");

    // A reply, recorded twice under the same logical key.
    sales_autopilot::experiments::record_reward(
        &pool,
        &tenant,
        experiment,
        "control",
        RewardKind::Reply,
        &outcome_key,
        0.0,
    )
    .await
    .expect("first reply");
    sales_autopilot::experiments::record_reward(
        &pool,
        &tenant,
        experiment,
        "control",
        RewardKind::Reply,
        &outcome_key,
        0.0,
    )
    .await
    .expect("replayed reply must be a no-op, not an error");
    // Even a different rung under the same key does not move anything.
    sales_autopilot::experiments::record_reward(
        &pool,
        &tenant,
        experiment,
        "control",
        RewardKind::Complaint,
        &outcome_key,
        0.0,
    )
    .await
    .expect("conflicting replay must be ignored");

    let (alpha, beta, trials, successes, contacts, negative): (f64, f64, i64, i64, i64, i64) =
        sqlx::query_as(
            "SELECT alpha, beta, trials, successes, contacts, negative_outcomes \
             FROM sales_experiment_arms WHERE experiment_id = $1 AND variant = 'control'",
        )
        .bind(experiment)
        .fetch_one(&pool)
        .await
        .expect("read arm");
    assert!((alpha - 1.2).abs() < 1e-9, "alpha {alpha}");
    assert!((beta - 1.0).abs() < 1e-9, "beta {beta}");
    assert_eq!(trials, 1, "one logical outcome must be one trial");
    assert_eq!(successes, 1);
    assert_eq!(contacts, 1);
    assert_eq!(
        negative, 0,
        "the conflicting complaint replay must not count"
    );

    let ledger_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_experiment_outcomes \
         WHERE experiment_id = $1 AND outcome_key = $2",
    )
    .bind(experiment)
    .bind(&outcome_key)
    .fetch_one(&pool)
    .await
    .expect("count ledger");
    assert_eq!(ledger_rows, 1);

    // Opens are recorded and counted as exposure but never move the posterior.
    for index in 0..3 {
        sales_autopilot::experiments::record_reward(
            &pool,
            &tenant,
            experiment,
            "control",
            RewardKind::Open,
            &format!("open-{run}-{index}"),
            0.0,
        )
        .await
        .expect("record open");
    }
    let (alpha, beta, trials, contacts): (f64, f64, i64, i64) = sqlx::query_as(
        "SELECT alpha, beta, trials, contacts FROM sales_experiment_arms \
         WHERE experiment_id = $1 AND variant = 'control'",
    )
    .bind(experiment)
    .fetch_one(&pool)
    .await
    .expect("read arm after opens");
    assert!((alpha - 1.2).abs() < 1e-9, "opens must not move alpha");
    assert!((beta - 1.0).abs() < 1e-9, "opens must not move beta");
    assert_eq!(trials, 1, "opens are not informative trials");
    assert_eq!(contacts, 4, "opens count exposure");
}

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn hostile_reward_inputs_fail_before_any_write() {
    let Some(pool) = common::test_pool("reward_hostile").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "reward-hostile").await;
    let experiment = insert_experiment(
        &pool,
        &tenant,
        &format!("exp-{}", unique_suffix()),
        serde_json::json!({}),
        serde_json::json!([]),
    )
    .await;

    let huge_key = "k".repeat(1_048_576);
    for (label, key, value) in [
        ("oversized key", huge_key.as_str(), 0.0),
        ("empty key", "", 0.0),
        ("NaN value", "k", f64::NAN),
        ("negative value", "k", -1.0),
        ("infinite value", "k", f64::INFINITY),
    ] {
        let error = sales_autopilot::experiments::record_reward(
            &pool,
            &tenant,
            experiment,
            "control",
            RewardKind::Reply,
            key,
            value,
        )
        .await
        .expect_err(label);
        assert!(
            matches!(error, SalesError::InvalidInput(_)),
            "{label}: {error:?}"
        );
    }

    // Unknown arm / unknown experiment also fail before writing.
    let error = sales_autopilot::experiments::record_reward(
        &pool,
        &tenant,
        experiment,
        "does-not-exist",
        RewardKind::Reply,
        "k",
        0.0,
    )
    .await
    .expect_err("unknown arm");
    assert!(matches!(error, SalesError::InvalidInput(_)));
    let error = sales_autopilot::experiments::record_reward(
        &pool,
        &tenant,
        Uuid::new_v4(),
        "control",
        RewardKind::Reply,
        "k",
        0.0,
    )
    .await
    .expect_err("unknown experiment");
    assert!(matches!(error, SalesError::InvalidInput(_)));

    let ledger_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_experiment_outcomes WHERE experiment_id = $1",
    )
    .bind(experiment)
    .fetch_one(&pool)
    .await
    .expect("count ledger");
    assert_eq!(ledger_rows, 0, "hostile inputs must write nothing");
}

// ---------------------------------------------------------------------------
// §18 — contextual fallback and shrinkage
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn sparse_context_bucket_falls_back_to_global_and_a_populated_one_takes_over() {
    let Some(pool) = common::test_pool("context_fallback").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "context-fallback").await;
    let account = insert_account(&pool, &tenant, "saas", "DE", 30).await;
    let key = format!("exp-{}", unique_suffix());
    let _experiment = insert_experiment(
        &pool,
        &tenant,
        &key,
        serde_json::json!({}),
        serde_json::json!(["icp_segment", "country", "company_size_band"]),
    )
    .await;

    let engine = ExperimentEngine::new(pool.clone());
    let loaded = engine
        .load_experiment(&tenant, &key)
        .await
        .expect("load experiment")
        .expect("experiment exists");
    let context = VariantContext {
        dimensions: ExperimentContext {
            icp_segment: Some("saas".into()),
            country: Some("DE".into()),
            company_size_band: Some("11-50".into()),
            ..ExperimentContext::default()
        },
        sender_domain_exposure: 0,
        daily_exploration_pct: 0.0,
        account_expected_value_eur: 0.0,
        explicit_exploration_override: false,
    };

    // Sparse bucket: the global posterior is authoritative and is never a
    // random arm — it is one of the experiment's arms.
    let first = engine
        .select_variant(&tenant, &loaded, &context)
        .await
        .expect("first selection");
    assert!(
        !first.used_context_bucket,
        "a bucket with no observations must fall back to global: {}",
        first.reason
    );
    assert_eq!(first.experiment_id, loaded.id);
    assert!(matches!(first.variant.as_str(), "control" | "challenger"));
    assert!(first.explore);

    // The bucket experiment was provisioned lazily.
    let bucket_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM sales_experiments \
         WHERE tenant_id = $1 AND context->>'parent_key' = $2",
    )
    .bind(&tenant)
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("bucket experiment exists");

    // Populate the bucket beyond MIN_CONTEXT_SAMPLES with a decisive
    // challenger posterior.
    sqlx::query(
        "UPDATE sales_experiment_arms SET alpha = 50, beta = 1, trials = $2 \
         WHERE experiment_id = $1 AND variant = 'challenger'",
    )
    .bind(bucket_id)
    .bind(MIN_CONTEXT_SAMPLES + 100)
    .execute(&pool)
    .await
    .expect("strengthen bucket challenger");
    sqlx::query(
        "UPDATE sales_experiment_arms SET alpha = 1, beta = 50, trials = $2 \
         WHERE experiment_id = $1 AND variant = 'control'",
    )
    .bind(bucket_id)
    .bind(MIN_CONTEXT_SAMPLES + 100)
    .execute(&pool)
    .await
    .expect("weaken bucket control");

    let second = engine
        .select_variant(&tenant, &loaded, &context)
        .await
        .expect("second selection");
    assert!(
        second.used_context_bucket,
        "a bucket with >= MIN_CONTEXT_SAMPLES must use its own posterior: {}",
        second.reason
    );
    assert_eq!(
        second.experiment_id, bucket_id,
        "rewards must be attributable to the authoritative bucket experiment"
    );
    assert_eq!(
        second.variant, "challenger",
        "the bucket posterior must win: {}",
        second.reason
    );

    // A context where every dimension is absent uses the global posterior and
    // never panics.
    let empty = engine
        .select_variant(
            &tenant,
            &loaded,
            &VariantContext {
                dimensions: ExperimentContext::default(),
                ..VariantContext::default()
            },
        )
        .await
        .expect("empty-context selection");
    assert!(!empty.used_context_bucket);
    assert_eq!(empty.experiment_id, loaded.id);
    assert!(matches!(empty.variant.as_str(), "control" | "challenger"));
    let _ = account;
}

// ---------------------------------------------------------------------------
// §37 — budgets enforced through the engine
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn zero_and_exhausted_contact_budgets_are_exploit_only_and_deterministic() {
    let Some(pool) = common::test_pool("budget_exhaustion").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "budget-exhaustion").await;
    let engine = ExperimentEngine::new(pool.clone());

    // Zero means ZERO: no exploration immediately.
    let zero_key = format!("zero-{}", unique_suffix());
    let zero_id = insert_experiment(
        &pool,
        &tenant,
        &zero_key,
        serde_json::json!({ "max_contacts": 0, "high_value_ev_threshold_eur": null }),
        serde_json::json!([]),
    )
    .await;
    let zero = engine
        .load_experiment(&tenant, &zero_key)
        .await
        .unwrap()
        .unwrap();
    let first = engine
        .select_variant(&tenant, &zero, &VariantContext::default())
        .await
        .expect("zero-budget selection");
    assert!(!first.explore, "{}", first.reason);
    assert!(first.reason.contains("contact budget exhausted"));
    for _ in 0..5 {
        let again = engine
            .select_variant(&tenant, &zero, &VariantContext::default())
            .await
            .expect("repeat");
        assert_eq!(
            again.variant, first.variant,
            "exploit-only must be deterministic"
        );
        assert!(!again.explore);
    }
    let _ = zero_id;

    // Budget spent: 10 recorded contacts exhaust max_contacts = 10.
    let spent_key = format!("spent-{}", unique_suffix());
    let spent_id = insert_experiment(
        &pool,
        &tenant,
        &spent_key,
        serde_json::json!({ "max_contacts": 10, "high_value_ev_threshold_eur": null }),
        serde_json::json!([]),
    )
    .await;
    let run = unique_suffix();
    for index in 0..10 {
        sales_autopilot::experiments::record_reward(
            &pool,
            &tenant,
            spent_id,
            "control",
            RewardKind::Open,
            &format!("exhaust-{run}-{index}"),
            0.0,
        )
        .await
        .expect("record contact");
    }
    let spent = engine
        .load_experiment(&tenant, &spent_key)
        .await
        .unwrap()
        .unwrap();
    let verdict = engine
        .select_variant(&tenant, &spent, &VariantContext::default())
        .await
        .expect("exhausted selection");
    assert!(!verdict.explore, "{}", verdict.reason);
    assert!(verdict.reason.contains("contact budget exhausted"));
    let repeat = engine
        .select_variant(&tenant, &spent, &VariantContext::default())
        .await
        .expect("repeat");
    assert_eq!(repeat.variant, verdict.variant);
}

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn high_value_accounts_are_exploit_only_unless_explicitly_overridden() {
    let Some(pool) = common::test_pool("high_value").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "high-value").await;
    let key = format!("hv-{}", unique_suffix());
    insert_experiment(
        &pool,
        &tenant,
        &key,
        serde_json::json!({}),
        serde_json::json!([]),
    )
    .await;
    let engine = ExperimentEngine::new(pool.clone());
    let experiment = engine
        .load_experiment(&tenant, &key)
        .await
        .unwrap()
        .unwrap();

    let high_value = VariantContext {
        account_expected_value_eur: 20_000.0,
        ..VariantContext::default()
    };
    let preserved = engine
        .select_variant(&tenant, &experiment, &high_value)
        .await
        .expect("high-value selection");
    assert!(!preserved.explore, "{}", preserved.reason);
    assert!(preserved.reason.contains("high-value account"));

    let overridden = VariantContext {
        explicit_exploration_override: true,
        ..high_value
    };
    let exploring = engine
        .select_variant(&tenant, &experiment, &overridden)
        .await
        .expect("overridden selection");
    assert!(exploring.explore, "override must re-enable exploration");
}

// ---------------------------------------------------------------------------
// §17 — variant persisted BEFORE the send survives an enqueue error
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn variant_is_persisted_before_send_and_survives_enqueue_failure() {
    let Some(pool) = common::test_pool("variant_persist").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "variant-persist").await;
    let domain = common::unique_test_domain();
    common::insert_verified_domain(&pool, &tenant, &domain).await;
    // The send path resolves a real sales sender identity before it claims the
    // step; without one the handler defers (retry) before the attempt and the
    // variant-persistence subject is never exercised. The identity also needs
    // a healthy sender-health row or the decision engine denies the send.
    let sender_id = common::insert_sender_identity(
        &pool,
        &tenant,
        "sales_outbound",
        &format!("sales@{domain}"),
        &domain,
        "active",
    )
    .await;
    sqlx::query(
        "INSERT INTO sales_sender_health (id, tenant_id, sender_identity_id, health_score, state) \
         VALUES (gen_random_uuid(), $1, $2, 0.99, 'healthy')",
    )
    .bind(&tenant)
    .bind(sender_id)
    .execute(&pool)
    .await
    .expect("insert sales_sender_health fixture");
    let template_id = common::insert_template(
        &pool,
        &tenant,
        "Hi {{first_name}}",
        "<p>Hello {{first_name}} from {{company}}</p>",
        Some("Hello {{first_name}}"),
    )
    .await;
    // A jurisdiction whose policy permits an autonomous send (the fail-closed
    // migration defaults make every EU/EEA recipient approval-required, which
    // would park the work before the variant-persistence assertion).
    let account = insert_account(&pool, &tenant, "saas", common::TEST_JURISDICTION, 30).await;
    common::ensure_allowed_jurisdiction_policy(&pool).await;
    let contact = insert_contact(&pool, &tenant, account).await;
    insert_contact_point(&pool, &tenant, contact, "cto@example.com").await;
    let key = format!("send-{}", unique_suffix());
    insert_experiment(
        &pool,
        &tenant,
        &key,
        serde_json::json!({}),
        serde_json::json!(["icp_segment", "country"]),
    )
    .await;
    let (version_id, step_id) = insert_sequence_chain(
        &pool,
        &tenant,
        "Experiment send",
        Some(&template_id),
        Some(&key),
    )
    .await;
    let enrollment =
        insert_enrollment(&pool, &tenant, account, contact, version_id, "active").await;
    let step_execution =
        insert_step_execution(&pool, &tenant, enrollment, version_id, step_id, "scheduled").await;
    set_autonomy(&pool, &tenant, "autonomous_guarded").await;

    let dispatcher = Arc::new(
        ProductionCampaignDispatcher::new(
            common::test_dispatch_config_for(&domain),
            pool.clone(),
            Arc::new(FailingAdmissionBackend),
        )
        .expect("dispatcher config valid"),
    );
    let handler = SequenceStepHandler::new(pool.clone(), dispatcher);
    // The handler attaches the decision packet through the action fence, so
    // the action must be a REAL leased row (enqueued + claimed exactly like
    // the production worker claim) rather than a synthetic struct: a
    // synthetic fence is not verifiable and the handler would retry before
    // ever reaching the send attempt.
    let action = common::enqueue_send_step_action(&pool, &tenant, step_execution).await;
    let worker_id = format!("variant-persist-worker-{}", Uuid::new_v4().simple());
    let leased = common::claim_specific_action(&pool, &worker_id, action.id)
        .await
        .expect("the enqueued send action must be claimable");
    let outcome = handler.handle(&leased).await;
    assert!(
        matches!(outcome, ActionOutcome::Retry(_)),
        "the simulated quota outage must surface as a retry, got {outcome:?}"
    );

    let (variant, state): (String, String) =
        sqlx::query_as("SELECT variant, state FROM sales_step_executions WHERE id = $1")
            .bind(step_execution)
            .fetch_one(&pool)
            .await
            .expect("read step execution");
    assert!(
        matches!(variant.as_str(), "control" | "challenger"),
        "the experiment variant must be persisted before the send (got '{variant}')"
    );
    assert_eq!(state, "executing", "the send was attempted");
    let (experiment_id, experiment_variant): (Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT experiment_id, experiment_variant FROM sales_enrollments WHERE id = $1",
    )
    .bind(enrollment)
    .fetch_one(&pool)
    .await
    .expect("read enrollment");
    assert!(
        experiment_id.is_some(),
        "enrollment must carry the experiment id"
    );
    assert_eq!(experiment_variant.as_deref(), Some(variant.as_str()));

    common::cleanup_tenant(&pool, &tenant).await;
}

// ---------------------------------------------------------------------------
// §28 — the next-best-action gate against live state
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn next_best_action_gate_skips_a_weak_prospect_with_a_recorded_reason() {
    let Some(pool) = common::test_pool("nba_gate").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "nba-gate").await;
    let account = insert_account(&pool, &tenant, "saas", "DE", 30).await;
    let contact = insert_contact(&pool, &tenant, account).await;
    insert_contact_point(&pool, &tenant, contact, "cto@example.com").await;
    let (version_id, _step_id) =
        insert_sequence_chain(&pool, &tenant, "Gate sequence", None, None).await;
    let enrollment =
        insert_enrollment(&pool, &tenant, account, contact, version_id, "active").await;

    // A weak prospect: latest score EV below the outreach floor.
    sqlx::query(
        "INSERT INTO sales_scores (
            id, tenant_id, account_id, contact_id, p_qualified_reply, p_meeting, p_paid,
            expected_value_eur, total, intent, evidence_quality, scoring_version, computed_at
         ) VALUES (gen_random_uuid(), $1, $2, $3, 0.05, 0.05, 0.01, 1.50, 10, 5, 20, 'test', NOW())",
    )
    .bind(&tenant)
    .bind(account)
    .bind(contact)
    .execute(&pool)
    .await
    .expect("insert score");

    let skip = sales_autopilot::sequence_worker::next_best_action_skip_reason(
        &pool,
        &tenant,
        Some(account),
        contact,
        enrollment,
        false,
    )
    .await
    .expect("gate evaluation")
    .expect("a weak prospect must be gated");
    assert!(skip.contains("next_best_action=do_nothing"), "{skip}");
    assert!(skip.contains("minimum"), "{skip}");

    // A high-value account with thin evidence gets an information action, not
    // a contact.
    sqlx::query(
        "INSERT INTO sales_scores (
            id, tenant_id, account_id, contact_id, p_qualified_reply, p_meeting, p_paid,
            expected_value_eur, total, intent, evidence_quality, scoring_version, computed_at
         ) VALUES (gen_random_uuid(), $1, $2, $3, 0.3, 0.3, 0.2, 25000, 70, 40, 30, 'test', NOW())",
    )
    .bind(&tenant)
    .bind(account)
    .bind(contact)
    .execute(&pool)
    .await
    .expect("insert high-value score");
    let skip = sales_autopilot::sequence_worker::next_best_action_skip_reason(
        &pool,
        &tenant,
        Some(account),
        contact,
        enrollment,
        false,
    )
    .await
    .expect("gate evaluation")
    .expect("thin evidence on a high-EV account must be gated");
    assert!(
        skip.contains("next_best_action=research_company")
            || skip.contains("next_best_action=collect_evidence")
            || skip.contains("next_best_action=enrich")
            || skip.contains("next_best_action=verify_email"),
        "{skip}"
    );

    // With a human reply the gate must never allow a send.
    let skip = sales_autopilot::sequence_worker::next_best_action_skip_reason(
        &pool,
        &tenant,
        Some(account),
        contact,
        enrollment,
        true,
    )
    .await
    .expect("gate evaluation")
    .expect("a reply must gate");
    assert!(skip.contains("next_best_action=operator_task"), "{skip}");

    // And the pure policy agrees with the live gate.
    let input = NextActionInput {
        expected_value_eur: 1.5,
        evidence_count: 0,
        email: EmailState::Verified,
        reply: ReplyState::None,
        ..NextActionInput::default()
    };
    assert_eq!(next_best_action(&input).0, DecisionAction::DoNothing);
}

// ---------------------------------------------------------------------------
// §36 — calibration joins predictions to realisations
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn calibration_measures_scores_against_realised_outcomes() {
    let Some(pool) = common::test_pool("calibrate_live").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "calibrate-live").await;
    let account = insert_account(&pool, &tenant, "saas", "DE", 30).await;
    let contact = insert_contact(&pool, &tenant, account).await;

    // Three scores at staggered instants, so the earlier scores have observed
    // realisations and the newest does not (a documented negative example).
    for hours_ago in [3_i32, 2, 1] {
        sqlx::query(
            "INSERT INTO sales_scores (
                id, tenant_id, account_id, contact_id, p_qualified_reply, p_meeting, p_paid,
                expected_value_eur, total, scoring_version, computed_at
             ) VALUES (gen_random_uuid(), $1, $2, $3, 0.7, 0.7, 0.7, 100, 50, 'test-v',
                       NOW() - make_interval(hours => $4))",
        )
        .bind(&tenant)
        .bind(account)
        .bind(contact)
        .bind(hours_ago)
        .execute(&pool)
        .await
        .expect("insert score");
    }
    // positive_reply at -150 minutes (after scores 1 and 2), paid at -90 minutes.
    for (outcome, value, minutes_ago) in [
        ("positive_reply", 0.0, 150_i32),
        ("paid_subscription", 500.0, 90),
    ] {
        sqlx::query(
            "INSERT INTO sales_outcomes (id, tenant_id, account_id, contact_id, outcome, value_eur, occurred_at) \
             VALUES (gen_random_uuid(), $1, $2, $3, $4, $5::float8::numeric, \
                     NOW() - make_interval(mins => $6))",
        )
        .bind(&tenant)
        .bind(account)
        .bind(contact)
        .bind(outcome)
        .bind(value)
        .bind(minutes_ago)
        .execute(&pool)
        .await
        .expect("insert outcome");
    }

    let window = sales_autopilot::attribution::AttributionWindow::new(
        Utc::now() - Duration::hours(4),
        Utc::now() + Duration::hours(1),
    );
    let reports = sales_autopilot::calibration::calibrate(&pool, &tenant, window)
        .await
        .expect("calibrate");
    assert_eq!(reports.len(), 3);
    for report in &reports {
        assert_eq!(
            report.n, 3,
            "{} must see the three score rows",
            report.metric
        );
        assert!(report.brier_score.is_finite());
        assert!(report.log_loss.is_finite());
        assert!((report.mean_predicted - 0.7).abs() < 1e-9);
        assert!(!report.overconfident, "small n must not be flagged");
        assert!(sales_autopilot::calibration::may_promote(report, 1, 1.0));
    }
    // Scores at -3h and -2h observed the paid subscription; the -1h score did
    // not, so the realised rate is 2/3.
    let paid = reports
        .iter()
        .find(|report| report.metric == sales_autopilot::calibration::METRIC_PAID)
        .expect("paid report");
    assert!(
        (paid.observed_rate - 2.0 / 3.0).abs() < 1e-9,
        "observed {}",
        paid.observed_rate
    );
    let qualified = reports
        .iter()
        .find(|report| report.metric == sales_autopilot::calibration::METRIC_QUALIFIED_REPLY)
        .expect("qualified report");
    assert!((qualified.observed_rate - 2.0 / 3.0).abs() < 1e-9);
    let meeting = reports
        .iter()
        .find(|report| report.metric == sales_autopilot::calibration::METRIC_MEETING)
        .expect("meeting report");
    assert_eq!(meeting.observed_rate, 0.0);
}

// ---------------------------------------------------------------------------
// §35 — historical replay reads canonical state
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn replay_cases_compare_proposed_actions_with_realised_outcomes() {
    let Some(pool) = common::test_pool("replay_live").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "replay-live").await;
    let account = insert_account(&pool, &tenant, "saas", "DE", 120).await;
    let contact = insert_contact(&pool, &tenant, account).await;
    let as_of = Utc::now() - Duration::hours(2);

    sqlx::query(
        "INSERT INTO sales_decisions (
            id, tenant_id, account_id, contact_id, action, expected_value_eur, confidence,
            score_total, autonomy_mode, rationale, blocked, block_reasons, created_at,
            enforcement, review_status
         ) VALUES (gen_random_uuid(), $1, $2, $3, 'contact', 100, 0.6, 50, 'autonomous_guarded',
                   'integration replay fixture', FALSE, '[]'::jsonb, $4,
                   'execute', 'not_required')",
    )
    .bind(&tenant)
    .bind(account)
    .bind(contact)
    .bind(as_of)
    .execute(&pool)
    .await
    .expect("insert decision");

    let mut record = OutcomeRecord::new(OutcomeKind::PaidSubscription);
    record.account_id = Some(account);
    record.contact_id = Some(contact);
    record.value_eur = 750.0;
    record.occurred_at = Some(as_of + Duration::hours(1));
    sales_autopilot::attribution::record_outcome(&pool, &tenant, &record)
        .await
        .expect("record realised outcome");

    let cases = sales_autopilot::simulation::load_replay_cases(
        &pool,
        &tenant,
        (as_of - Duration::hours(1), Utc::now() + Duration::hours(1)),
        50,
    )
    .await
    .expect("load replay cases");
    assert_eq!(cases.len(), 1, "one historical decision point");
    assert_eq!(cases[0].realised, Some(OutcomeKind::PaidSubscription));
    assert!((cases[0].realised_value_eur - 750.0).abs() < 1e-6);
    assert!(cases[0].features.legal != sales_autopilot::types::ContactDecision::Prohibited);

    #[derive(Debug)]
    struct AlwaysContact;
    impl sales_autopilot::simulation::Policy for AlwaysContact {
        fn decide(&self, _case: &sales_autopilot::simulation::ReplayCase) -> DecisionAction {
            DecisionAction::Contact
        }
    }
    let result = sales_autopilot::simulation::replay(&cases, &AlwaysContact);
    assert_eq!(result.cases, 1);
    assert_eq!(result.agreements, 1, "reality rewarded a contact (paid)");
    assert_eq!(result.realised_actions.get("paid_subscription"), Some(&1));
    assert!(
        result.expected_value_error_eur < 0.0,
        "realised 750 EUR vs modelled EV below that must be negative: {}",
        result.expected_value_error_eur
    );

    // The scoring version used for the replay is the production version.
    assert!(!scoring::SCORING_VERSION.is_empty());

    common::cleanup_tenant(&pool, &tenant).await;
}

// ---------------------------------------------------------------------------
// §12/§26 — research writes grounded evidence; an outage writes nothing
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FailingIntelligence;

#[async_trait::async_trait]
impl SalesIntelligence for FailingIntelligence {
    async fn research_account(
        &self,
        _req: &ResearchRequest<'_>,
    ) -> Result<ResearchFindings, IntelligenceError> {
        Err(IntelligenceError::Unavailable(
            "simulated AI outage: connection refused".into(),
        ))
    }

    async fn select_angle(
        &self,
        _req: &AngleRequest<'_>,
    ) -> Result<AngleSelection, IntelligenceError> {
        Err(IntelligenceError::Unavailable("simulated outage".into()))
    }

    async fn draft_message(
        &self,
        _req: &DraftRequest<'_>,
    ) -> Result<DraftedMessage, IntelligenceError> {
        Err(IntelligenceError::Unavailable("simulated outage".into()))
    }

    async fn classify_reply(
        &self,
        _req: &ReplyRequest<'_>,
    ) -> Result<ReplyClassification, IntelligenceError> {
        Err(IntelligenceError::Unavailable("simulated outage".into()))
    }

    async fn determine_next_action(
        &self,
        _req: &NextActionRequest<'_>,
    ) -> Result<DecisionAction, IntelligenceError> {
        Err(IntelligenceError::Unavailable("simulated outage".into()))
    }
}

#[derive(Debug)]
struct ScriptedIntelligence {
    grounded_evidence_id: Uuid,
}

#[async_trait::async_trait]
impl SalesIntelligence for ScriptedIntelligence {
    async fn research_account(
        &self,
        _req: &ResearchRequest<'_>,
    ) -> Result<ResearchFindings, IntelligenceError> {
        Ok(ResearchFindings {
            claims: vec![
                ResearchClaim {
                    proposition: "They use SendGrid".into(),
                    confidence: 0.8,
                    source_kind: Some("dns_observation".into()),
                    source_ref: Some("spf include".into()),
                    evidence_id: Some(self.grounded_evidence_id),
                    is_hypothesis: false,
                },
                ResearchClaim {
                    proposition: "They may be replatforming".into(),
                    confidence: 0.5,
                    source_kind: Some("provider_api".into()),
                    source_ref: None,
                    evidence_id: None,
                    is_hypothesis: true,
                },
                ResearchClaim {
                    proposition: "They raised a Series B".into(),
                    confidence: 0.9,
                    source_kind: Some("provider_api".into()),
                    source_ref: None,
                    evidence_id: None,
                    is_hypothesis: false,
                },
                ResearchClaim {
                    proposition: "They employ 10 000 people".into(),
                    confidence: 0.9,
                    source_kind: Some("provider_api".into()),
                    source_ref: None,
                    evidence_id: Some(Uuid::new_v4()),
                    is_hypothesis: false,
                },
            ],
            model_version: Some("scripted-1".into()),
            fallback: None,
        })
    }

    async fn select_angle(
        &self,
        _req: &AngleRequest<'_>,
    ) -> Result<AngleSelection, IntelligenceError> {
        Err(IntelligenceError::NotConfigured("scripted".into()))
    }

    async fn draft_message(
        &self,
        _req: &DraftRequest<'_>,
    ) -> Result<DraftedMessage, IntelligenceError> {
        Err(IntelligenceError::NotConfigured("scripted".into()))
    }

    async fn classify_reply(
        &self,
        _req: &ReplyRequest<'_>,
    ) -> Result<ReplyClassification, IntelligenceError> {
        Err(IntelligenceError::NotConfigured("scripted".into()))
    }

    async fn determine_next_action(
        &self,
        _req: &NextActionRequest<'_>,
    ) -> Result<DecisionAction, IntelligenceError> {
        Err(IntelligenceError::NotConfigured("scripted".into()))
    }
}

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn ai_outage_writes_zero_evidence_rows_and_says_why() {
    let Some(pool) = common::test_pool("ai_outage").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "ai-outage").await;
    let account = insert_account(&pool, &tenant, "saas", "DE", 30).await;

    let run = sales_autopilot::research::research_account_with_report(
        &pool,
        &tenant,
        account,
        &FailingIntelligence,
    )
    .await
    .expect("an outage is a successful run that writes nothing");
    assert_eq!(run.mode, ResearchMode::Outage);
    assert!(run.evidence_ids.is_empty());
    assert_eq!(run.accepted, 0);
    let reason = run.reason.expect("outage must say why");
    assert!(reason.contains("connection refused"), "{reason}");
    assert!(reason.contains("no evidence written"), "{reason}");

    let evidence_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_evidence WHERE tenant_id = $1 AND account_id = $2",
    )
    .bind(&tenant)
    .bind(account)
    .fetch_one(&pool)
    .await
    .expect("count evidence");
    assert_eq!(evidence_rows, 0, "an outage must fabricate nothing");
}

#[tokio::test]
#[ignore = "live Postgres: set TEST_DATABASE_URL"]
async fn research_writes_only_grounded_claims_and_labels_hypotheses() {
    let Some(pool) = common::test_pool("research_grounded").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&pool, "research-grounded").await;
    let account = insert_account(&pool, &tenant, "saas", "DE", 30).await;

    // One pre-existing grounded evidence row, which is the only citable id.
    let grounded_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sales_evidence (
            id, tenant_id, account_id, proposition, confidence, source_kind, observed_at
         ) VALUES (gen_random_uuid(), $1, $2, 'SPF includes sendgrid.net', 0.7, 'dns_observation', NOW())
         RETURNING id",
    )
    .bind(&tenant)
    .bind(account)
    .fetch_one(&pool)
    .await
    .expect("insert grounded evidence");

    let run = sales_autopilot::research::research_account_with_report(
        &pool,
        &tenant,
        account,
        &ScriptedIntelligence {
            grounded_evidence_id: grounded_id,
        },
    )
    .await
    .expect("research run");
    assert_eq!(run.mode, ResearchMode::Ai);
    assert_eq!(run.accepted, 2, "one grounded claim and one hypothesis");
    assert_eq!(run.omitted.len(), 2, "unevidenced + hallucinated citations");
    assert!(run
        .omitted
        .iter()
        .any(|omitted| omitted.reason.contains("unevidenced")));
    assert!(run
        .omitted
        .iter()
        .any(|omitted| omitted.reason.contains("not in the allowed set")));

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT proposition, source_kind FROM sales_evidence \
         WHERE tenant_id = $1 AND account_id = $2 AND id <> $3 ORDER BY proposition",
    )
    .bind(&tenant)
    .bind(account)
    .bind(grounded_id)
    .fetch_all(&pool)
    .await
    .expect("read new evidence");
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .any(|(proposition, _)| proposition.starts_with(HYPOTHESIS_PREFIX)));
    assert!(rows.iter().any(
        |(proposition, source_kind)| proposition == "They use SendGrid"
            && source_kind == "dns_observation"
    ));
}
