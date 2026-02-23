//! Functional tests for sales-autopilot: CRM, enrichment, campaigns, calendar, inbox.

use chrono::{NaiveDate, Utc};

use sales_autopilot::crm::CrmService;
use sales_autopilot::enrichment::EnrichmentService;
use sales_autopilot::campaigns::CampaignManager;
use sales_autopilot::calendar::CalendarService;
use sales_autopilot::inbox::InboxManager;
use sales_autopilot::types::*;

fn date(y: i32, m: u32, d: u32, h: u32, min: u32) -> chrono::DateTime<Utc> {
    NaiveDate::from_ymd_opt(y, m, d)
        .unwrap()
        .and_hms_opt(h, min, 0)
        .unwrap()
        .and_utc()
}

// ── Lead scoring ───────────────────────────────────────────────

#[test]
fn lead_score_high_engagement_big_company() {
    let score = CrmService::score_lead(0.9, 0.8, 0.7);
    assert!(score >= 70, "high engagement + big company should score high, got {}", score);
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

#[test]
fn categorize_lead_message() {
    let inbox = InboxManager::new();
    let msg = inbox.categorize_message("prospect@x.com".into(), "Interested in a demo".into());
    assert_eq!(msg.category, MessageCategory::Lead);
}

#[test]
fn categorize_customer_message() {
    let inbox = InboxManager::new();
    let msg = inbox.categorize_message("user@x.com".into(), "Invoice question".into());
    assert_eq!(msg.category, MessageCategory::Customer);
}

#[test]
fn categorize_support_message() {
    let inbox = InboxManager::new();
    let msg = inbox.categorize_message("user@x.com".into(), "Need help with ticket".into());
    assert_eq!(msg.category, MessageCategory::Support);
}

#[test]
fn categorize_spam_message() {
    let inbox = InboxManager::new();
    let msg = inbox.categorize_message("noreply@spam.com".into(), "Buy Viagra now".into());
    assert_eq!(msg.category, MessageCategory::Spam);
}

// ── Campaign state transitions ─────────────────────────────────

#[test]
fn campaign_lifecycle_draft_active_paused() {
    let mgr = CampaignManager::new(10);
    let c = mgr.create_campaign("Drip".into(), "tmpl_1".into(), "leads".into()).unwrap();
    assert_eq!(c.status, CampaignStatus::Draft);

    let started = mgr.start_campaign(c.id).unwrap();
    assert_eq!(started.status, CampaignStatus::Active);

    let paused = mgr.pause_campaign(c.id).unwrap();
    assert_eq!(paused.status, CampaignStatus::Paused);

    // Re-start from paused
    let restarted = mgr.start_campaign(c.id).unwrap();
    assert_eq!(restarted.status, CampaignStatus::Active);
}

// ── Calendar availability ──────────────────────────────────────

#[test]
fn calendar_within_working_hours() {
    let svc = CalendarService::new();
    let start = date(2026, 3, 2, 10, 0);
    let end   = date(2026, 3, 2, 10, 30);
    let evt = svc.create_event("Demo".into(), vec!["a@x.com".into()], start, end, None);
    assert!(evt.is_ok());
}

#[test]
fn calendar_outside_working_hours_rejected() {
    let svc = CalendarService::new();
    let start = date(2026, 3, 2, 20, 0);  // 8 PM
    let end   = date(2026, 3, 2, 20, 30);
    let res = svc.create_event("Late call".into(), vec![], start, end, None);
    assert!(res.is_err(), "events outside 09-17 should be rejected");
}

#[test]
fn calendar_overlap_rejected() {
    let svc = CalendarService::new();
    let s = date(2026, 3, 2, 10, 0);
    let e = date(2026, 3, 2, 10, 30);
    svc.create_event("A".into(), vec![], s, e, None).unwrap();
    // Same slot should fail
    let res = svc.create_event("B".into(), vec![], s, e, None);
    assert!(res.is_err());
}

// ── CRM search ─────────────────────────────────────────────────

#[test]
fn crm_search_by_name() {
    let svc = CrmService::new();
    svc.create_lead("alice@acme.com".into(), "Alice Smith".into(), "Acme".into(), "CTO".into(), "web".into());
    svc.create_lead("bob@beta.io".into(), "Bob Jones".into(), "Beta".into(), "CEO".into(), "web".into());

    let results = svc.search_leads("alice");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Alice Smith");

    // "." is a literal substring and matches ".com" / ".io" in emails
    let all = svc.search_leads(".");
    assert_eq!(all.len(), 2);

    // A truly non-matching query returns empty
    let none = svc.search_leads("zzzzz");
    assert_eq!(none.len(), 0);
}

// ── Reply rate (campaign stats) ────────────────────────────────

#[test]
fn campaign_stats_track_sends() {
    let mgr = CampaignManager::new(10);
    let c = mgr.create_campaign("Test".into(), "tmpl".into(), "all".into()).unwrap();
    mgr.add_recipients(c.id, vec!["a@x.com".into(), "b@x.com".into()]).unwrap();

    let stats = mgr.get_stats(c.id).unwrap();
    assert_eq!(stats["recipients"], 2);
    assert_eq!(stats["sent"], 0);
}
