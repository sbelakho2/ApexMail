//! Live-DB adversarial tests for the enrichment waterfall (§9), cost-aware
//! routing (§10) and real discovery (§6).
//!
//! Every test is `#[ignore]`d: they need the canonical migrated schema.
//! Run them with:
//!
//! ```sh
//! TEST_DATABASE_URL=postgresql://… cargo test -p sales-autopilot \
//!   --test enrichment_discovery -- --ignored --test-threads=1
//! ```
//!
//! The suite provisions its own dedicated database through the production
//! migrator (see `common/mod.rs`), so it never touches an ambient dev DB.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use uuid::Uuid;

use sales_autopilot::discovery::{
    promote_candidate, DiscoveredCandidate, DiscoveryError, DiscoveryJobRunner, DiscoveryQuery,
    FixtureSource,
};
use sales_autopilot::enrichment::{
    fields, router, EnrichmentError, EnrichmentProvider, EnrichmentRequest, EnrichmentService,
    ProviderId, ProviderPayload,
};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// A controllable live provider: fixed payload, optional failure, call count.
#[derive(Debug)]
struct LiveStubProvider {
    id: ProviderId,
    fields: Vec<&'static str>,
    payload: ProviderPayload,
    cost_eur: f64,
    fail: bool,
    calls: Arc<AtomicUsize>,
}

impl LiveStubProvider {
    fn new(id: &'static str, field: &'static str, value: &str, confidence: f32) -> Self {
        Self {
            id: ProviderId(id),
            fields: vec![field],
            payload: ProviderPayload::new().with(
                field,
                serde_json::Value::String(value.into()),
                confidence,
            ),
            cost_eur: 0.0,
            fail: false,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn failing(id: &'static str, field: &'static str) -> Self {
        Self {
            id: ProviderId(id),
            fields: vec![field],
            payload: ProviderPayload::new(),
            cost_eur: 0.0,
            fail: true,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn with_cost(mut self, cost: f64) -> Self {
        self.cost_eur = cost;
        self
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for LiveStubProvider {
    fn id(&self) -> ProviderId {
        self.id
    }

    fn fields(&self) -> &[&'static str] {
        &self.fields
    }

    fn cost_eur(&self) -> f64 {
        self.cost_eur
    }

    async fn fetch(
        &self,
        _request: &EnrichmentRequest<'_>,
    ) -> Result<ProviderPayload, EnrichmentError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(EnrichmentError::Unavailable("stub provider failure".into()))
        } else {
            Ok(self.payload.clone())
        }
    }
}

fn candidate(source_url: &str) -> DiscoveredCandidate {
    DiscoveredCandidate {
        source: "fixture".into(),
        source_url: Some(source_url.into()),
        company_name: Some("Fixture Co".into()),
        domain: Some("fixture.example".into()),
        jurisdiction: Some("EE".into()),
        jurisdiction_confidence: 0.9,
        confidence: 0.7,
        raw_snapshot_hash: Some("abc123".into()),
    }
}

fn fixture(
    id: &'static str,
    candidates: Vec<DiscoveredCandidate>,
) -> Arc<dyn sales_autopilot::discovery::DiscoverySource> {
    Arc::new(FixtureSource::new(id, candidates))
}

// ---------------------------------------------------------------------------
// §9 — waterfall persistence, provenance, partial failure
// ---------------------------------------------------------------------------

/// Facts are the source of truth: each persisted row names the provider that
/// supplied it, carries non-zero confidence and links to an evidence row.
#[ignore]
#[tokio::test]
async fn live_waterfall_persists_provenance_per_field() {
    let Some(db) = common::test_pool("live_waterfall_persists_provenance_per_field").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "enrich-prov").await;

    let provider_a = LiveStubProvider::new("live_provider_a", fields::INDUSTRY, "SaaS", 0.9);
    let provider_b =
        LiveStubProvider::new("live_provider_b", fields::FUNDING_STAGE, "Series A", 0.6);
    let service =
        EnrichmentService::from_providers(vec![Arc::new(provider_a), Arc::new(provider_b)]);

    let persisted = service
        .enrich_persisted(
            &db,
            &tenant,
            "waterfall-live.example",
            Some("bob@waterfall-live.example"),
            Some("Waterfall Live"),
        )
        .await
        .expect("enrichment must succeed");

    assert_eq!(persisted.outcome.facts.len(), 2);

    let rows: Vec<(String, String, f64, Option<Uuid>)> = sqlx::query_as(
        "SELECT field, provider, confidence, evidence_id
         FROM sales_enrichment_facts
         WHERE tenant_id = $1 AND subject_id = $2
         ORDER BY field",
    )
    .bind(&tenant)
    .bind(persisted.account_id)
    .fetch_all(&db)
    .await
    .expect("facts query");
    assert_eq!(rows.len(), 2);

    let industry = rows
        .iter()
        .find(|(field, ..)| field == fields::INDUSTRY)
        .expect("industry fact");
    assert_eq!(
        industry.1, "live_provider_a",
        "field filled by provider 1 must be attributed to provider 1"
    );
    assert!(industry.2 > 0.0, "persisted confidence must be non-zero");
    assert!(industry.3.is_some(), "fact must link to evidence");

    let funding = rows
        .iter()
        .find(|(field, ..)| field == fields::FUNDING_STAGE)
        .expect("funding fact");
    assert_eq!(
        funding.1, "live_provider_b",
        "field filled by provider 2 must be attributed to provider 2, not the waterfall"
    );

    // Evidence rows are real.
    let evidence_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_evidence WHERE tenant_id = $1 AND account_id = $2",
    )
    .bind(&tenant)
    .bind(persisted.account_id)
    .fetch_one(&db)
    .await
    .expect("evidence count");
    assert_eq!(evidence_count, 2);

    // The account exists and the legacy projection was refreshed from facts.
    let account: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sales_accounts WHERE id = $1 AND tenant_id = $2")
            .bind(persisted.account_id)
            .bind(&tenant)
            .fetch_one(&db)
            .await
            .expect("account count");
    assert_eq!(account, 1);

    let projected: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM enriched_companies WHERE tenant_id = $1 AND domain = $2",
    )
    .bind(&tenant)
    .bind("waterfall-live.example")
    .fetch_one(&db)
    .await
    .expect("projection count");
    assert_eq!(projected, 1);
}

/// Provider 1 errors, provider 2 still fills its fields, the run reports
/// partial coverage, and the failure lands in `sales_provider_stats`.
#[ignore]
#[tokio::test]
async fn live_partial_failure_is_survivable_and_recorded() {
    let Some(db) = common::test_pool("live_partial_failure_is_survivable_and_recorded").await
    else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "enrich-partial").await;

    let failing = Arc::new(LiveStubProvider::failing("live_flaky", fields::INDUSTRY));
    let healthy = Arc::new(
        LiveStubProvider::new("live_healthy", fields::FUNDING_STAGE, "Seed", 0.7).with_cost(0.004),
    );
    let service = EnrichmentService::from_providers(vec![failing.clone(), healthy.clone()]);

    let persisted = service
        .enrich_persisted(&db, &tenant, "partial-live.example", None, None)
        .await
        .expect("partial enrichment must still succeed");

    assert!(persisted.outcome.is_partial());
    assert_eq!(persisted.outcome.provider_failures.len(), 1);
    assert!(persisted.outcome.fact(fields::FUNDING_STAGE).is_some());
    assert_eq!(persisted.outcome.facts.len(), 1);

    let flaky: (i64, i64, i64, f64) = sqlx::query_as(
        "SELECT attempts, fills, errors, total_cost_eur::float8
         FROM sales_provider_stats
         WHERE tenant_id = $1 AND provider = 'live_flaky' AND field = $2",
    )
    .bind(&tenant)
    .bind(fields::INDUSTRY)
    .fetch_one(&db)
    .await
    .expect("flaky stats");
    assert_eq!(flaky.0, 1, "one attempt recorded");
    assert_eq!(flaky.1, 0, "no fill on failure");
    assert_eq!(flaky.2, 1, "one error recorded");
    assert_eq!(
        flaky.3, 0.0,
        "total_cost_eur must not grow on a failed lookup"
    );

    let healthy_stats: (i64, i64, i64, f64) = sqlx::query_as(
        "SELECT attempts, fills, errors, total_cost_eur::float8
         FROM sales_provider_stats
         WHERE tenant_id = $1 AND provider = 'live_healthy' AND field = $2",
    )
    .bind(&tenant)
    .bind(fields::FUNDING_STAGE)
    .fetch_one(&db)
    .await
    .expect("healthy stats");
    assert_eq!(healthy_stats.0, 1);
    assert_eq!(healthy_stats.1, 1);
    assert_eq!(healthy_stats.2, 0);
    assert!(healthy_stats.3 > 0.0, "cost recorded on a successful fill");
}

// ---------------------------------------------------------------------------
// §10 — routing from real statistics
// ---------------------------------------------------------------------------

/// Cold start (no stats) explores; after enough failures the dead provider is
/// dropped in favour of an alternative; cost only moves on a fill.
#[ignore]
#[tokio::test]
async fn live_router_cold_start_dead_provider_and_cost_accounting() {
    let Some(db) =
        common::test_pool("live_router_cold_start_dead_provider_and_cost_accounting").await
    else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "router").await;

    let cheap = LiveStubProvider::new("router_cheap", fields::EMPLOYEE_COUNT, "50-200", 0.9)
        .with_cost(0.002);
    let pricey = LiveStubProvider::new("router_pricey", fields::EMPLOYEE_COUNT, "50-200", 0.9)
        .with_cost(0.03);

    // Cold start: no rows → priors → the cheaper provider explores.
    let candidates: Vec<&dyn EnrichmentProvider> = vec![&cheap, &pricey];
    let choice = router::choose_provider(&db, &tenant, fields::EMPLOYEE_COUNT, &candidates)
        .await
        .expect("routing query")
        .expect("router must not refuse at cold start");
    assert_eq!(choice.provider, ProviderId("router_cheap"));
    assert!(choice.score > 0.0);

    // Cost/latency/verification accounting.
    for _ in 0..3 {
        router::record_attempt(&db, &tenant, cheap.id(), fields::EMPLOYEE_COUNT)
            .await
            .expect("attempt");
    }
    router::record_fill(&db, &tenant, cheap.id(), fields::EMPLOYEE_COUNT)
        .await
        .expect("fill");
    router::record_cost(&db, &tenant, cheap.id(), fields::EMPLOYEE_COUNT, 0.002)
        .await
        .expect("cost");
    router::record_latency(&db, &tenant, cheap.id(), fields::EMPLOYEE_COUNT, 120)
        .await
        .expect("latency");
    router::record_verified_correct(&db, &tenant, cheap.id(), fields::EMPLOYEE_COUNT, 1)
        .await
        .expect("verified");

    let stats: (i64, i64, i64, i64, f64, i64) = sqlx::query_as(
        "SELECT attempts, fills, verified_correct, total_latency_ms, total_cost_eur::float8, errors
         FROM sales_provider_stats
         WHERE tenant_id = $1 AND provider = $2 AND field = $3",
    )
    .bind(&tenant)
    .bind("router_cheap")
    .bind(fields::EMPLOYEE_COUNT)
    .fetch_one(&db)
    .await
    .expect("cheap stats");
    assert_eq!(stats, (3, 1, 1, 120, 0.002, 0));

    // Errors do not move cost.
    router::record_attempt(&db, &tenant, pricey.id(), fields::EMPLOYEE_COUNT)
        .await
        .expect("attempt");
    router::record_error(&db, &tenant, pricey.id(), fields::EMPLOYEE_COUNT)
        .await
        .expect("error");
    let pricey_stats: (i64, i64, f64) = sqlx::query_as(
        "SELECT attempts, errors, total_cost_eur::float8
         FROM sales_provider_stats
         WHERE tenant_id = $1 AND provider = $2 AND field = $3",
    )
    .bind(&tenant)
    .bind("router_pricey")
    .bind(fields::EMPLOYEE_COUNT)
    .fetch_one(&db)
    .await
    .expect("pricey stats");
    assert_eq!(pricey_stats, (1, 1, 0.0));

    // A proven-dead provider (0 fills, all errors) loses to a fresh
    // alternative that still explores.
    let dead = LiveStubProvider::new("router_dead", fields::INDUSTRY, "X", 0.5);
    let fresh = LiveStubProvider::new("router_fresh", fields::INDUSTRY, "Y", 0.5);
    for _ in 0..5 {
        router::record_attempt(&db, &tenant, dead.id(), fields::INDUSTRY)
            .await
            .expect("dead attempt");
        router::record_error(&db, &tenant, dead.id(), fields::INDUSTRY)
            .await
            .expect("dead error");
    }
    let candidates: Vec<&dyn EnrichmentProvider> = vec![&dead, &fresh];
    let choice = router::choose_provider(&db, &tenant, fields::INDUSTRY, &candidates)
        .await
        .expect("routing query")
        .expect("a choice");
    assert_eq!(
        choice.provider,
        ProviderId("router_fresh"),
        "a provider with zero coverage after real attempts must be dropped for exploration"
    );
}

/// The §10 example over real rows: equal coverage, A at €0.002 beats B at
/// €0.03; with B's coverage much higher, B can win.
#[ignore]
#[tokio::test]
async fn live_routing_cost_example_matches_section_10() {
    let Some(db) = common::test_pool("live_routing_cost_example_matches_section_10").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "router-cost").await;

    let provider_a =
        LiveStubProvider::new("cost_a", fields::EMPLOYEE_COUNT, "50-200", 0.9).with_cost(0.002);
    let provider_b =
        LiveStubProvider::new("cost_b", fields::EMPLOYEE_COUNT, "50-200", 0.9).with_cost(0.03);

    // Equal coverage 94/100, equal accuracy, equal freshness.
    for provider in ["cost_a", "cost_b"] {
        for _ in 0..100 {
            router::record_attempt(&db, &tenant, ProviderId(provider), fields::EMPLOYEE_COUNT)
                .await
                .expect("attempt");
        }
        for _ in 0..94 {
            router::record_fill(&db, &tenant, ProviderId(provider), fields::EMPLOYEE_COUNT)
                .await
                .expect("fill");
        }
        for _ in 0..94 {
            router::record_verified_correct(
                &db,
                &tenant,
                ProviderId(provider),
                fields::EMPLOYEE_COUNT,
                1,
            )
            .await
            .expect("verified");
        }
        router::record_cost(
            &db,
            &tenant,
            ProviderId(provider),
            fields::EMPLOYEE_COUNT,
            94.0 * if provider == "cost_a" { 0.002 } else { 0.03 },
        )
        .await
        .expect("cost");
    }

    let candidates: Vec<&dyn EnrichmentProvider> = vec![&provider_a, &provider_b];
    let choice = router::choose_provider(&db, &tenant, fields::EMPLOYEE_COUNT, &candidates)
        .await
        .expect("routing query")
        .expect("a choice");
    assert_eq!(
        choice.provider,
        ProviderId("cost_a"),
        "high coverage + low cost must beat equal coverage at 15x cost"
    );

    // Flip: B now has full coverage, A only 30%.
    for _ in 0..6 {
        router::record_fill(&db, &tenant, provider_b.id(), fields::EMPLOYEE_COUNT)
            .await
            .expect("fill b");
    }
    for _ in 0..30 {
        router::record_attempt(&db, &tenant, provider_a.id(), fields::EMPLOYEE_COUNT)
            .await
            .expect("attempt a");
        router::record_error(&db, &tenant, provider_a.id(), fields::EMPLOYEE_COUNT)
            .await
            .expect("error a");
    }
    let choice = router::choose_provider(&db, &tenant, fields::EMPLOYEE_COUNT, &candidates)
        .await
        .expect("routing query")
        .expect("a choice");
    assert_eq!(
        choice.provider,
        ProviderId("cost_b"),
        "much higher expected information gain must be able to justify 15x cost"
    );
}

// ---------------------------------------------------------------------------
// §6 — discovery dedupe / jurisdiction / promotion / hostile input / cost
// ---------------------------------------------------------------------------

/// Running the same query twice creates one candidate row (partial unique
/// index) and the second run does not double-count `discovered`.
#[ignore]
#[tokio::test]
async fn live_discovery_dedupe_across_jobs() {
    let Some(db) = common::test_pool("live_discovery_dedupe_across_jobs").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "discovery-dedupe").await;

    let source = fixture(
        "dedupe_fixture",
        vec![
            candidate("https://fixture.example/company/a"),
            candidate("https://fixture.example/company/b"),
        ],
    );
    let runner = DiscoveryJobRunner::new(db.clone(), vec![source]);
    let query = DiscoveryQuery {
        keywords: vec!["saas".into()],
        max_results: 100,
        ..DiscoveryQuery::default()
    };

    let first = runner
        .create_job(&tenant, &query, &["dedupe_fixture".to_string()])
        .await
        .expect("create job 1");
    let first = runner
        .run_to_completion(&tenant, first.id)
        .await
        .expect("run job 1");
    assert_eq!(first.status, "completed");
    assert_eq!(first.discovered, 2);

    let second = runner
        .create_job(&tenant, &query, &["dedupe_fixture".to_string()])
        .await
        .expect("create job 2");
    let second = runner
        .run_to_completion(&tenant, second.id)
        .await
        .expect("run job 2");
    assert_eq!(second.status, "completed");
    assert_eq!(
        second.discovered, 0,
        "a re-run must not double-count already-known candidates"
    );

    let candidates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_discovery_candidates
         WHERE tenant_id = $1 AND source = 'dedupe_fixture'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("candidate count");
    assert_eq!(candidates, 2, "one row per (tenant, source, source_url)");

    let source_runs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_source_runs WHERE tenant_id = $1 AND job_id = $2",
    )
    .bind(&tenant)
    .bind(first.id)
    .fetch_one(&db)
    .await
    .expect("source run count");
    assert_eq!(source_runs, 1, "one run row per source per run");
}

/// A source restricted to EE must have its US candidate dropped, and the drop
/// must be visible in the run record.
#[ignore]
#[tokio::test]
async fn live_discovery_jurisdiction_control_drops_and_reports() {
    let Some(db) = common::test_pool("live_discovery_jurisdiction_control_drops_and_reports").await
    else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "discovery-jurisdiction").await;

    let mut estonian = candidate("https://fixture.example/jurisdiction/ee");
    estonian.jurisdiction = Some("EE".into());
    let mut american = candidate("https://fixture.example/jurisdiction/us");
    american.jurisdiction = Some("US".into());
    let mut unknown = candidate("https://fixture.example/jurisdiction/unknown");
    unknown.jurisdiction = None;

    let source = Arc::new(
        FixtureSource::new("jurisdiction_fixture", vec![estonian, american, unknown])
            .with_allowed_jurisdictions(vec!["EE"]),
    );
    let runner = DiscoveryJobRunner::new(db.clone(), vec![source]);
    let job = runner
        .create_job(
            &tenant,
            &DiscoveryQuery {
                max_results: 100,
                ..DiscoveryQuery::default()
            },
            &["jurisdiction_fixture".to_string()],
        )
        .await
        .expect("create job");
    let job = runner
        .run_to_completion(&tenant, job.id)
        .await
        .expect("run job");

    assert_eq!(job.discovered, 2, "EE + unknown jurisdiction persisted");
    let us_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_discovery_candidates
         WHERE tenant_id = $1 AND source_url = 'https://fixture.example/jurisdiction/us'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("US candidate count");
    assert_eq!(
        us_rows, 0,
        "candidate from a disallowed jurisdiction is dropped"
    );

    let run_error: Option<String> = sqlx::query_scalar(
        "SELECT error FROM sales_source_runs WHERE tenant_id = $1 AND job_id = $2",
    )
    .bind(&tenant)
    .bind(job.id)
    .fetch_one(&db)
    .await
    .expect("run record");
    let run_error = run_error.expect("drop must be visible in the run record");
    assert!(
        run_error.contains("jurisdiction_filter") && run_error.contains('1'),
        "run record must name the dropped jurisdiction count: {run_error}"
    );
}

/// Promotion refuses a domain-less candidate with a clear error and is
/// idempotent for a valid one (exactly one sales_accounts row).
#[ignore]
#[tokio::test]
async fn live_promotion_is_idempotent_and_refuses_without_domain() {
    let Some(db) =
        common::test_pool("live_promotion_is_idempotent_and_refuses_without_domain").await
    else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "promotion").await;

    let mut no_domain = candidate("https://fixture.example/promote/no-domain");
    no_domain.domain = None;
    let valid = candidate("https://fixture.example/promote/valid");
    let mut valid = valid;
    valid.domain = Some("promote-live.example".into());

    let source = fixture("promotion_fixture", vec![no_domain, valid]);
    let runner = DiscoveryJobRunner::new(db.clone(), vec![source]);
    let job = runner
        .create_job(
            &tenant,
            &DiscoveryQuery {
                max_results: 100,
                ..DiscoveryQuery::default()
            },
            &["promotion_fixture".to_string()],
        )
        .await
        .expect("create job");
    let job = runner
        .run_to_completion(&tenant, job.id)
        .await
        .expect("run job");

    let valid_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM sales_discovery_candidates
         WHERE tenant_id = $1 AND source_url = 'https://fixture.example/promote/valid'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("valid candidate id");
    let no_domain_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM sales_discovery_candidates
         WHERE tenant_id = $1 AND source_url = 'https://fixture.example/promote/no-domain'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("domain-less candidate id");

    // Domain-less candidate → precise refusal.
    let error = promote_candidate(&db, &tenant, no_domain_id)
        .await
        .expect_err("promotion must refuse a candidate without a domain");
    assert!(
        error.to_string().contains("domain"),
        "error must say why promotion was refused: {error}"
    );

    // Valid candidate → one account row, idempotent on re-promotion.
    let account_id = promote_candidate(&db, &tenant, valid_id)
        .await
        .expect("promote valid candidate");
    let account_id_again = promote_candidate(&db, &tenant, valid_id)
        .await
        .expect("re-promote valid candidate");
    assert_eq!(account_id, account_id_again);

    let accounts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_accounts WHERE tenant_id = $1 AND domain = 'promote-live.example'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("account count");
    assert_eq!(accounts, 1, "promotion twice must not create two accounts");

    let job_after = runner.get_job(&tenant, job.id).await.expect("job reload");
    assert_eq!(
        job_after.imported, 1,
        "imported counts the first promotion only"
    );

    let stamped: Option<Uuid> = sqlx::query_scalar(
        "SELECT promoted_account_id FROM sales_discovery_candidates WHERE id = $1",
    )
    .bind(valid_id)
    .fetch_one(&db)
    .await
    .expect("stamp query");
    assert_eq!(stamped, Some(account_id));
}

/// A hostile provider cannot write malformed rows: over-long domains, missing
/// domains, non-URLs, empty hashes and out-of-range confidences are sanitized;
/// the CHECK constraints reject anything that slips through.
#[ignore]
#[tokio::test]
async fn live_discovery_hostile_input_is_sanitized() {
    let Some(db) = common::test_pool("live_discovery_hostile_input_is_sanitized").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "discovery-hostile").await;

    let mut overlong = candidate("https://hostile.example/overlong-domain");
    overlong.company_name = Some("Overlong Domain".into());
    overlong.domain = Some("a".repeat(4_096));

    let mut missing_domain = candidate("https://hostile.example/missing-domain");
    missing_domain.company_name = Some("Missing Domain".into());
    missing_domain.domain = None;

    let mut bad_url = candidate("not a url");
    bad_url.company_name = Some("Bad URL".into());

    let mut empty_hash = candidate("https://hostile.example/empty-hash");
    empty_hash.raw_snapshot_hash = Some(String::new());

    let mut absurd_confidence = candidate("https://hostile.example/confidence");
    absurd_confidence.confidence = 5.0;
    absurd_confidence.jurisdiction_confidence = -3.0;

    let mut candidates = vec![
        overlong,
        missing_domain,
        bad_url,
        empty_hash,
        absurd_confidence,
    ];
    // A provider ignoring max_results and returning 10 000 candidates.
    for index in 0..10_000 {
        let mut bulk = candidate(&format!("https://hostile.example/bulk/{index}"));
        bulk.domain = Some(format!("hostile-{index}.example"));
        candidates.push(bulk);
    }

    let source: Arc<dyn sales_autopilot::discovery::DiscoverySource> = Arc::new(
        FixtureSource::new("hostile_fixture", candidates)
            .with_page_size(1_000)
            .with_cost_per_page_eur(0.01),
    );
    let runner = DiscoveryJobRunner::new(db.clone(), vec![source]);
    let job = runner
        .create_job(
            &tenant,
            &DiscoveryQuery {
                // Empty keywords must be a valid, non-panicking query.
                keywords: Vec::new(),
                max_results: 1_000,
                ..DiscoveryQuery::default()
            },
            &["hostile_fixture".to_string()],
        )
        .await
        .expect("create hostile job");

    // One bounded batch: 3 pages × at most 1000 candidates.
    let job = runner
        .run_job(
            &tenant,
            job.id,
            sales_autopilot::discovery::MAX_PAGES_PER_RUN,
        )
        .await
        .expect("hostile batch must not fail");
    assert!(
        job.discovered <= 3_000,
        "provider overflow must be truncated, got {}",
        job.discovered
    );

    let overlong_domain: Option<String> = sqlx::query_scalar(
        "SELECT account_domain FROM sales_discovery_candidates
         WHERE tenant_id = $1 AND source_url = 'https://hostile.example/overlong-domain'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("overlong row");
    assert!(
        overlong_domain.is_none(),
        "4 KB domain must be stored as NULL"
    );

    let missing_domain: Option<String> = sqlx::query_scalar(
        "SELECT account_domain FROM sales_discovery_candidates
         WHERE tenant_id = $1 AND source_url = 'https://hostile.example/missing-domain'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("missing domain row");
    assert!(missing_domain.is_none());

    let stored_url: Option<String> = sqlx::query_scalar(
        "SELECT source_url FROM sales_discovery_candidates
         WHERE tenant_id = $1 AND company_name = 'Bad URL'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("bad url query");
    assert!(
        stored_url.map_or(true, |value| value != "not a url"),
        "non-URL source_url must not be stored verbatim"
    );

    let empty_hash: Option<String> = sqlx::query_scalar(
        "SELECT raw_snapshot_hash FROM sales_discovery_candidates
         WHERE tenant_id = $1 AND source_url = 'https://hostile.example/empty-hash'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("empty hash row");
    assert!(empty_hash.is_none(), "empty hash must be stored as NULL");

    let confidence: f64 = sqlx::query_scalar(
        "SELECT confidence::float8 FROM sales_discovery_candidates
         WHERE tenant_id = $1 AND source_url = 'https://hostile.example/confidence'",
    )
    .bind(&tenant)
    .fetch_one(&db)
    .await
    .expect("confidence row");
    assert!(
        (confidence - 1.0).abs() < 1e-9,
        "confidence must be clamped"
    );

    // Row-level constraints the code relies on actually reject malformed rows.
    let bad_confidence = sqlx::query(
        "INSERT INTO sales_discovery_candidates (id, tenant_id, source, confidence)
         VALUES ($1, $2, 'constraint_probe', 2.0)",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant)
    .execute(&db)
    .await;
    assert!(
        bad_confidence.is_err(),
        "CHECK confidence <= 1 must reject out-of-range values"
    );

    let bad_factor = sqlx::query(
        "INSERT INTO sales_enrichment_facts
            (id, tenant_id, subject_type, subject_id, field, provider, confidence)
         VALUES ($1, $2, 'account', $3, 'industry', 'constraint_probe', 1.5)",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant)
    .bind(Uuid::new_v4())
    .execute(&db)
    .await;
    assert!(
        bad_factor.is_err(),
        "CHECK confidence <= 1 on sales_enrichment_facts must reject bad values"
    );
}

/// `sales_discovery_jobs.cost_eur` equals the sum of its source-run costs.
#[ignore]
#[tokio::test]
async fn live_discovery_cost_accounting_sums_source_runs() {
    let Some(db) = common::test_pool("live_discovery_cost_accounting_sums_source_runs").await
    else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "discovery-cost").await;

    let source_a = Arc::new(
        FixtureSource::new(
            "cost_fixture_a",
            vec![candidate("https://fixture.example/cost/a")],
        )
        .with_cost_per_page_eur(0.1),
    );
    let source_b = Arc::new(
        FixtureSource::new(
            "cost_fixture_b",
            vec![candidate("https://fixture.example/cost/b")],
        )
        .with_cost_per_page_eur(0.2),
    );
    let runner = DiscoveryJobRunner::new(db.clone(), vec![source_a, source_b]);
    let job = runner
        .create_job(
            &tenant,
            &DiscoveryQuery {
                max_results: 100,
                ..DiscoveryQuery::default()
            },
            &["cost_fixture_a".to_string(), "cost_fixture_b".to_string()],
        )
        .await
        .expect("create job");
    let job = runner
        .run_to_completion(&tenant, job.id)
        .await
        .expect("run job");

    let summed: f64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(cost_eur), 0)::float8 FROM sales_source_runs WHERE job_id = $1",
    )
    .bind(job.id)
    .fetch_one(&db)
    .await
    .expect("sum of run costs");
    assert!(
        (job.cost_eur - summed).abs() < 1e-9,
        "job cost {} must equal source-run sum {}",
        job.cost_eur,
        summed
    );
    assert!((job.cost_eur - 0.3).abs() < 1e-9);
}

/// A failing source is recorded as `failed`/`rate_limited` with its error, and
/// a job whose only source fails ends `failed` (not silently completed).
#[ignore]
#[tokio::test]
async fn live_discovery_source_failure_is_recorded() {
    let Some(db) = common::test_pool("live_discovery_source_failure_is_recorded").await else {
        return;
    };
    let tenant = common::insert_test_tenant(&db, "discovery-failure").await;

    let source = Arc::new(
        FixtureSource::new("failing_fixture", Vec::new())
            .failing(DiscoveryError::RateLimited("slow down".into())),
    );
    let runner = DiscoveryJobRunner::new(db.clone(), vec![source]);
    let job = runner
        .create_job(
            &tenant,
            &DiscoveryQuery::default(),
            &["failing_fixture".to_string()],
        )
        .await
        .expect("create job");
    let job = runner
        .run_to_completion(&tenant, job.id)
        .await
        .expect("run job");

    assert_eq!(job.status, "failed");
    assert!(job
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("slow down"));

    let run: (String, Option<String>) = sqlx::query_as(
        "SELECT status, error FROM sales_source_runs WHERE tenant_id = $1 AND job_id = $2",
    )
    .bind(&tenant)
    .bind(job.id)
    .fetch_one(&db)
    .await
    .expect("run record");
    assert_eq!(run.0, "rate_limited");
    assert!(run.1.unwrap_or_default().contains("slow down"));
}

/// `#[ignore]`d helper test: proving the suite itself is wired to the
/// requested database when run with `--ignored`.
#[ignore]
#[tokio::test]
async fn live_schema_has_required_sales_tables() {
    let Some(db) = common::test_pool("live_schema_has_required_sales_tables").await else {
        return;
    };
    sales_autopilot::routes::initialize_schema(&db)
        .await
        .expect("canonical schema must verify");
}
