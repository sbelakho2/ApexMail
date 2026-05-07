//! Functional tests for sales-autopilot:CRM, enrichment, campaigns, calendar, inbox.

use chrono::{NaiveDate, Utc};

use sales_autopilot::calendar::CalendarService;
use sales_autopilot::campaigns::CampaignManager;
use sales_autopilot::crm::CrmService;
use sales_autopilot::enrichment::EnrichmentService;
use sales_autopilot::inbox::InboxManager;
use sales_autopilot::routes::initialize_schema;
use sales_autopilot::types::*;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use uuid::Uuid;

fn date(y: i32, m: u32, d: u32, h: u32, min: u32) -> chrono::DateTime<Utc> {
    NaiveDate::from_ymd_opt(y, m, d)
        .unwrap()
        .and_hms_opt(h, min, 0)
        .unwrap()
        .and_utc()
}

/// Create a test-only database pool using `connect_lazy` without TLS.
///
/// # Security note
/// This intentionally uses no TLS because it targets a local ephemeral database
/// (`postgres://localhost/unused`) that never leaves the test process.  In a
/// CI/test environment the connection URL is expected to point to a disposable
/// Postgres instance.  Do **not** use this helper against a production database.
fn lazy_db() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://localhost/unused")
        .expect("lazy pool")
}

async fn optional_db(test_name: &str) -> Option<sqlx::PgPool> {
    let database_url = match std::env::var("TEST_DATABASE_URL") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
            return None;
        }
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&database_url)
        .await
        .unwrap_or_else(|error| {
            panic!("TEST_DATABASE_URL is set but {test_name} could not connect: {error}")
        });
    initialize_schema(&pool).await.unwrap_or_else(|error| {
        panic!("failed to initialize sales schema for {test_name}: {error}")
    });
    Some(pool)
}

fn unique_tenant(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}

// ── Lead scoring ───────────────────────────────────────────────

#[test]
fn lead_score_high_engagement_big_company() {
    let score = CrmService::score_lead(0.9, 0.8, 0.7);
    assert!(
        score >= 70,
        "high engagement + big company should score high, got {}",
        score
    );
}

#[test]
fn lead_score_zero_engagement() {
    let score = CrmService::score_lead(0.0, 0.0, 0.0);
    assert_eq!(score, 0);
}

#[test]
fn lead_score_perfect_is_100() {
    assert_eq!(CrmService::score_lead(1.0, 1.0, 1.0), 100);
}

#[test]
fn lead_score_clamping() {
    // Values > 1.0 should be clamped
    assert_eq!(CrmService::score_lead(2.0, 2.0, 2.0), 100);
}

// ── Email extraction / enrichment ──────────────────────────────

#[test]
fn extract_domain_from_email() {
    assert_eq!(
        EnrichmentService::extract_domain("alice@acme.com"),
        Some("acme.com".to_string())
    );
    assert_eq!(
        EnrichmentService::extract_domain("BOB@Beta.IO"),
        Some("beta.io".to_string())
    );
    assert_eq!(EnrichmentService::extract_domain("nodomain"), None);
    assert_eq!(EnrichmentService::extract_domain("@"), None);
    assert_eq!(EnrichmentService::extract_domain(""), None);
}

#[test]
fn enrich_known_domain() {
    let svc = EnrichmentService::new("http://mock");
    let company = svc.enrich_company("acme.com").unwrap();
    assert_eq!(company.name, "Acme Corp");
    assert_eq!(company.industry, "SaaS");
    assert_eq!(company.size, "50-200");
}

#[test]
fn enrich_unknown_domain_returns_fallback() {
    let svc = EnrichmentService::new("http://mock");
    let c = svc.enrich_company("startup.xyz").unwrap();
    assert!(c.name.contains("Startup"));
    assert_eq!(c.industry, "Unknown");
}

// ── Message categorization ─────────────────────────────────────

#[tokio::test]
async fn categorize_lead_message() {
    let msg =
        InboxManager::classify_message("tenant-test".into(), "prospect@x.com".into(), "Interested in a demo".into());
    assert_eq!(msg.category, MessageCategory::Lead);
}

#[tokio::test]
async fn categorize_customer_message() {
    let msg = InboxManager::classify_message("tenant-test".into(), "user@x.com".into(), "Invoice question".into());
    assert_eq!(msg.category, MessageCategory::Customer);
}

#[tokio::test]
async fn categorize_support_message() {
    let msg = InboxManager::classify_message("tenant-test".into(), "user@x.com".into(), "Need help with ticket".into());
    assert_eq!(msg.category, MessageCategory::Support);
}

#[tokio::test]
async fn categorize_spam_message() {
    let msg = InboxManager::classify_message("tenant-test".into(), "noreply@spam.com".into(), "Buy Viagra now".into());
    assert_eq!(msg.category, MessageCategory::Spam);
}

// ── Campaign state transitions ─────────────────────────────────

#[tokio::test]
async fn campaign_lifecycle_draft_active_paused() {
    let Some(db) = optional_db("campaign_lifecycle_draft_active_paused").await else {
        return;
    };
    let mgr = CampaignManager::new(10, db);
    let tenant_id = unique_tenant("tenant-campaign-lifecycle");
    let c = mgr
        .create_campaign(
            tenant_id.clone(),
            "Drip".into(),
            "tmpl_1".into(),
            "leads".into(),
        )
        .await
        .unwrap();
    assert_eq!(c.status, CampaignStatus::Draft);

    let started = mgr.start_campaign(&tenant_id, c.id).await.unwrap();
    assert_eq!(started.status, CampaignStatus::Active);

    let paused = mgr.pause_campaign(&tenant_id, c.id).await.unwrap();
    assert_eq!(paused.status, CampaignStatus::Paused);

    // Re-start from paused
    let restarted = mgr.start_campaign(&tenant_id, c.id).await.unwrap();
    assert_eq!(restarted.status, CampaignStatus::Active);
}

// ── Calendar availability ──────────────────────────────────────

#[tokio::test]
async fn calendar_within_working_hours() {
    let Some(db) = optional_db("calendar_within_working_hours").await else {
        return;
    };
    let svc = CalendarService::new(db);
    let tenant_id = unique_tenant("tenant-calendar-working-hours");
    let start = date(2026, 3, 2, 10, 0);
    let end = date(2026, 3, 2, 10, 30);
    let evt = svc
        .create_event(
            tenant_id,
            "Demo".into(),
            vec!["a@x.com".into()],
            start,
            end,
            None,
        )
        .await;
    assert!(evt.is_ok());
}

#[tokio::test]
async fn calendar_outside_working_hours_rejected() {
    let svc = CalendarService::new(lazy_db());
    let start = date(2026, 3, 2, 20, 0); // 8 PM
    let end = date(2026, 3, 2, 20, 30);
    let res = svc
        .create_event(
            "tenant-a".into(),
            "Late call".into(),
            vec![],
            start,
            end,
            None,
        )
        .await;
    assert!(res.is_err(), "events outside 09-17 should be rejected");
}

#[tokio::test]
async fn calendar_overlap_rejected() {
    let Some(db) = optional_db("calendar_overlap_rejected").await else {
        return;
    };
    let svc = CalendarService::new(db);
    let tenant_id = unique_tenant("tenant-calendar-overlap");
    let s = date(2026, 3, 2, 10, 0);
    let e = date(2026, 3, 2, 10, 30);
    svc.create_event(tenant_id.clone(), "A".into(), vec![], s, e, None)
        .await
        .unwrap();
    // Same slot should fail
    let res = svc
        .create_event(tenant_id, "B".into(), vec![], s, e, None)
        .await;
    assert!(res.is_err());
}

// ── CRM search ─────────────────────────────────────────────────

#[test]
fn crm_search_by_name() {
    let svc = CrmService::new();
    svc.create_lead(
        "web".into(),
        "alice@acme.com".into(),
        "Alice Smith".into(),
        "Acme".into(),
        "CTO".into(),
        "web".into(),
    );
    svc.create_lead(
        "web".into(),
        "bob@beta.io".into(),
        "Bob Jones".into(),
        "Beta".into(),
        "CEO".into(),
        "web".into(),
    );

    let results = svc.search_leads("web", "alice");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Alice Smith");

    // "." is a literal substring and matches ".com" / ".io" in emails
    let all = svc.search_leads("web", ".");
    assert_eq!(all.len(), 2);

    // A truly non-matching query returns empty
    let none = svc.search_leads("web", "zzzzz");
    assert_eq!(none.len(), 0);
}

// ── Reply rate (campaign stats) ────────────────────────────────

#[tokio::test]
async fn campaign_stats_track_sends() {
    let Some(db) = optional_db("campaign_stats_track_sends").await else {
        return;
    };
    let mgr = CampaignManager::new(10, db);
    let tenant_id = unique_tenant("tenant-campaign-stats");
    let c = mgr
        .create_campaign(
            tenant_id.clone(),
            "Test".into(),
            "tmpl".into(),
            "all".into(),
        )
        .await
        .unwrap();
    mgr.add_recipients(&tenant_id, c.id, vec!["a@x.com".into(), "b@x.com".into()])
        .await
        .unwrap();

    let stats = mgr.get_stats(&tenant_id, c.id).await.unwrap();
    assert_eq!(stats["recipients"], 2);
    assert_eq!(stats["sent"], 0);
}
