//! F85 canonical-schema tests for the campaign autopilot's arm store
//! (campaign_arms + campaign_arm_outcomes, migration 197): arms are created
//! through the workflow producer, outcomes replay idempotently across a
//! restart, ownership is verified, and the report matches the ingested
//! outcomes.
//!
//! Gated on `TEST_DATABASE_URL` (workspace convention). The record paths do
//! not require Redis (only selection does), so no redis-server is needed.

use analytics::campaign_autopilot::CampaignAutopilot;
use sqlx::PgPool;
use uuid::Uuid;

async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
    migrator::test_support::fresh_canonical_pool("analytics_f85", db_suffix).await
}

fn autopilot(pool: &PgPool) -> CampaignAutopilot {
    let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1/1")
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("lazy pool needs no server");
    CampaignAutopilot::new(pool.clone(), redis)
}

async fn seed_campaign(pool: &PgPool, tenant: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_campaigns (id, tenant_id, name, template_id, audience) \
         VALUES ($1, $2, 'f85 campaign', 'tpl-base', 'all')",
    )
    .bind(id)
    .bind(tenant)
    .execute(pool)
    .await
    .expect("seed campaign");
    id
}

/// Readiness: the canonical arm store exists after migration 197.
#[tokio::test]
async fn schema_ready_on_canonical_chain() {
    let Some(pool) = canonical_pool("ready").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    assert!(
        autopilot(&pool).schema_ready().await,
        "canonical migration 197 must create campaign_arms"
    );
    pool.close().await;
}

/// Create a two-arm campaign, ingest outcomes once under replay, restart,
/// and obtain a report whose counters match those outcomes — exactly.
#[tokio::test]
async fn outcomes_ingest_once_under_replay_and_survive_restart() {
    let Some(pool) = canonical_pool("replay").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let tenant = "tenant_f85_a";
    let campaign = seed_campaign(&pool, tenant).await;
    let campaign_id = campaign.to_string();

    let service = autopilot(&pool);
    service
        .ensure_arms(
            tenant,
            &campaign_id,
            &["tpl-a".to_string(), "tpl-b".to_string()],
        )
        .await
        .expect("arms created through the workflow producer");

    // Re-invoking ensure_arms must not reset accumulated statistics.
    service
        .ensure_arms(
            tenant,
            &campaign_id,
            &["tpl-a".to_string(), "tpl-b".to_string()],
        )
        .await
        .expect("ensure_arms is idempotent");

    // Ingest outcomes: arm 0 gets 3 successes + 1 failure; arm 1 gets 1
    // success. Then REPLAY every outcome verbatim (the crash/retry case):
    // the first pass inserts, the replay deduplicates.
    let outcomes = [
        (0_usize, true, "msg-1:opened"),
        (0, true, "msg-2:opened"),
        (0, true, "msg-3:opened"),
        (0, false, "msg-4"),
        (1, true, "msg-5:opened"),
    ];
    for pass in 0..2 {
        for &(arm, success, key) in outcomes.iter() {
            let inserted = service
                .record_outcome(tenant, &campaign_id, arm, success, key)
                .await
                .expect("outcome ingest");
            assert_eq!(
                inserted,
                pass == 0,
                "first pass inserts; the verbatim replay deduplicates"
            );
        }
    }

    // Restart: a fresh service instance over the same database.
    let restarted = autopilot(&pool);
    let report = restarted
        .report(tenant, &campaign_id)
        .await
        .expect("report after restart");

    assert_eq!(report.arms.len(), 2);
    assert_eq!(report.total_trials, 5, "replayed outcomes counted once");
    let arm0 = &report.arms[0];
    // Beta(1,1) prior + 4 observations: alpha = 4, beta = 2, trials = 4.
    assert!((arm0.alpha - 4.0).abs() < f64::EPSILON);
    assert!((arm0.beta - 2.0).abs() < f64::EPSILON);
    assert_eq!(arm0.trials, 4);
    assert_eq!(arm0.successes, 3);
    let arm1 = &report.arms[1];
    assert!((arm1.alpha - 2.0).abs() < f64::EPSILON);
    assert!((arm1.beta - 1.0).abs() < f64::EPSILON);
    assert_eq!(arm1.successes, 1);

    // The durable outcome ledger holds exactly one row per logical outcome.
    let ledger: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM campaign_arm_outcomes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(ledger, 5);

    pool.close().await;
}

/// Ownership verification: another tenant cannot create arms for, mutate or
/// read a campaign it does not own.
#[tokio::test]
async fn ownership_is_verified_on_every_path() {
    let Some(pool) = canonical_pool("ownership").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let owner = "tenant_owner";
    let attacker = "tenant_attacker";
    let campaign = seed_campaign(&pool, owner).await;
    let campaign_id = campaign.to_string();

    let service = autopilot(&pool);
    service
        .ensure_arms(owner, &campaign_id, &["tpl-a".to_string()])
        .await
        .expect("owner creates arms");

    assert!(
        service
            .ensure_arms(attacker, &campaign_id, &["tpl-x".to_string()])
            .await
            .is_err(),
        "foreign tenant cannot create arms"
    );
    assert!(
        service
            .record_outcome(attacker, &campaign_id, 0, true, "evil-key")
            .await
            .is_err(),
        "foreign tenant cannot record outcomes"
    );
    assert!(
        service
            .update_arm(attacker, &campaign_id, 0, true)
            .await
            .is_err(),
        "foreign tenant cannot update arms"
    );
    assert!(
        service.report(attacker, &campaign_id).await.is_err(),
        "the ownership join hides the campaign from foreign reports"
    );

    pool.close().await;
}

/// update_arm with a checked arm index: a missing arm is an error (0 rows),
/// never a silent success.
#[tokio::test]
async fn update_arm_checks_affected_rows() {
    let Some(pool) = canonical_pool("affected").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let tenant = "tenant_rows";
    let campaign = seed_campaign(&pool, tenant).await;
    let campaign_id = campaign.to_string();

    let service = autopilot(&pool);
    let err = service
        .update_arm(tenant, &campaign_id, 7, true)
        .await
        .expect_err("arm 7 was never created");
    assert!(
        err.to_string().contains("does not exist"),
        "error must name the missing arm: {err}"
    );

    // And an out-of-range index cannot wrap the i32 conversion.
    let err = service
        .update_arm(tenant, &campaign_id, usize::MAX, true)
        .await
        .expect_err("usize::MAX is not a valid arm index");
    assert!(err.to_string().contains("out of range"));

    pool.close().await;
}
