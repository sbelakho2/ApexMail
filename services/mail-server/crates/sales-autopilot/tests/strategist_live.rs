//! Live-database test for the message strategist builder (audit §14).
//!
//! The pure composition/validation logic is unit-tested in
//! `personalization.rs`; this test proves the **async builder's SQL** against
//! the canonical schema: every column it reads
//! (`sales_accounts`, `sales_contacts`, `sales_evidence`, `sales_signals`,
//! `sales_enrichment_facts`, `sales_reply_classifications`) exists with the
//! expected type, and the resulting strategy carries the evidence id of the
//! inserted row.
//!
//! `#[ignore]`d; run with:
//!
//! ```text
//! TEST_DATABASE_URL=postgresql://user:pass@host:5432/db \
//!   cargo test -p sales-autopilot --test strategist_live -- --ignored
//! ```

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use sales_autopilot::knowledge::SalesKnowledgeBase;
use sales_autopilot::personalization::{MessageStrategist, StrategyRequest};

const LIVE_DB: &str = "apexmail_calendar_live";

async fn live_pool(test_name: &str) -> Option<PgPool> {
    let base_url = std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let pool = match migrator::test_support::shared_canonical_db(&base_url, LIVE_DB).await {
        Ok(Some(pool)) => pool,
        Ok(None) => return None,
        Err(error) => panic!("{test_name}: {}", error.panic_message()),
    };
    sales_autopilot::routes::initialize_schema(&pool)
        .await
        .unwrap_or_else(|error| {
            panic!("canonical schema verification failed for {test_name}: {error}")
        });
    Some(pool)
}

#[tokio::test]
#[ignore = "live database required"]
async fn live_db_strategist_builds_from_canonical_tables() {
    let Some(pool) = live_pool("live_db_strategist_builds_from_canonical_tables").await else {
        eprintln!("skipping: TEST_DATABASE_URL unset");
        return;
    };
    let tenant = format!("strat-live-{}", Uuid::new_v4().simple());
    let account_id = Uuid::new_v4();
    let contact_id = Uuid::new_v4();
    let evidence_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO sales_accounts (id, tenant_id, company, domain, country, industry, employees, technologies, esp_hypotheses) \
         VALUES ($1, $2, 'Acme Ltd', 'acme.example', 'EE', 'SaaS', 120, ARRAY['sendgrid','ruby'], '[{\"proposition\":\"may be outgrowing the current ESP\"}]'::jsonb)",
    )
    .bind(account_id)
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("insert account");

    sqlx::query(
        "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name, job_title, persona, country, timezone, language) \
         VALUES ($1, $2, $3, 'Ada Lovelace', 'CTO', 'technical', 'EE', 'Europe/Tallinn', 'en')",
    )
    .bind(contact_id)
    .bind(&tenant)
    .bind(account_id)
    .execute(&pool)
    .await
    .expect("insert contact");

    sqlx::query(
        "INSERT INTO sales_evidence (id, tenant_id, account_id, contact_id, proposition, confidence, source_kind, source_ref, observed_at) \
         VALUES ($1, $2, $3, $4, 'Acme uses SendGrid for transactional email.', 0.92, 'http_fetch', 'https://acme.example/stack', NOW())",
    )
    .bind(evidence_id)
    .bind(&tenant)
    .bind(account_id)
    .bind(contact_id)
    .execute(&pool)
    .await
    .expect("insert evidence");

    sqlx::query(
        "INSERT INTO sales_signals (id, tenant_id, account_id, signal_type, strength, observed_at, expires_at, evidence_id, payload) \
         VALUES ($1, $2, $3, 'hiring_engineering', 0.8, NOW(), $4, $5, '{}'::jsonb)",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant)
    .bind(account_id)
    .bind(Utc::now() + Duration::days(30))
    .bind(evidence_id)
    .execute(&pool)
    .await
    .expect("insert signal");

    sqlx::query(
        "INSERT INTO sales_enrichment_facts (id, tenant_id, subject_type, subject_id, field, value, provider, confidence, evidence_id, observed_at) \
         VALUES ($1, $2, 'account', $3, 'email_provider', '\"sendgrid\"'::jsonb, 'test-provider', 0.9, $4, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant)
    .bind(account_id)
    .bind(evidence_id)
    .execute(&pool)
    .await
    .expect("insert enrichment fact");

    sqlx::query(
        "INSERT INTO sales_reply_classifications (id, tenant_id, contact_id, disposition, confidence, classifier, created_at) \
         VALUES ($1, $2, $3, 'question', 0.7, 'deterministic', NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant)
    .bind(contact_id)
    .execute(&pool)
    .await
    .expect("insert reply classification");

    let strategist = MessageStrategist::new(pool.clone(), SalesKnowledgeBase::canonical());
    let request = StrategyRequest {
        tenant_id: tenant.clone(),
        account_id,
        contact_id,
        enrollment_id: None,
        language: None,
        offer: "Growth plan for high-volume senders".into(),
        experiment_arm: None,
        now: Some(Utc::now()),
    };
    let strategy = strategist.build(&request).await.expect("build strategy");

    let observed = strategy
        .observed_fact
        .clone()
        .expect("evidence-backed observation");
    assert_eq!(observed.evidence_id, evidence_id);
    assert_eq!(
        observed.statement,
        "Acme uses SendGrid for transactional email."
    );
    assert!(
        strategy.problem_hypothesis.contains("hiring")
            || strategy.problem_hypothesis.contains("Acme")
    );
    assert!(!strategy.value_prop.is_empty());
    assert_eq!(strategy.language, "en");

    // No fabricated personalization, and rendering drops nothing needed here.
    let rendered = strategist
        .render(
            &strategy,
            &sales_autopilot::personalization::TemplateProseWriter::new(),
        )
        .expect("cold render");
    assert!(rendered.body.contains("SendGrid"));

    // Cleanup (unique tenant per run, but keep the shared DB tidy).
    let _ = sqlx::query("DELETE FROM sales_contacts WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM sales_accounts WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM sales_reply_classifications WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM sales_signals WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM sales_enrichment_facts WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await;
}
