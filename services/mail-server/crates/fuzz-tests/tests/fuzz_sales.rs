//! Fuzz tests for sales-autopilot functions.

use fuzz_tests::*;
use rand::Rng;
use sales_autopilot::crm::CrmService;
use sales_autopilot::enrichment::EnrichmentService;
use sales_autopilot::inbox::InboxManager;
use sales_autopilot::scrapers::WebScraper;
use sales_autopilot::types::MessageCategory;

#[test]
fn fuzz_lead_score_bounded() {
    // CrmService::score_lead must always return 0-100 for any inputs.
    let mut rng = rand::thread_rng();
    for _ in 0..10_000 {
        let engagement = random_f64_range(-10.0, 10.0);
        let company_size = random_f64_range(-10.0, 10.0);
        let recency = random_f64_range(-10.0, 10.0);
        let score = CrmService::score_lead(engagement, company_size, recency);
        assert!(
            score <= 100,
            "Lead score {score} exceeds 100 for eng={engagement}, size={company_size}, rec={recency}"
        );
    }
}

#[test]
fn fuzz_email_extraction_no_panic() {
    // Random text fed to extract_emails_from_text must never cause a panic.
    let scraper = WebScraper::new();
    for _ in 0..5_000 {
        let text = random_unicode(rand::thread_rng().gen_range(0..500));
        let emails = scraper.extract_emails_from_text(&text);
        // Emails found should all contain '@'
        for email in &emails {
            assert!(email.contains('@'), "Extracted non-email: {email}");
        }
    }
    // Edge cases
    let _ = scraper.extract_emails_from_text("");
    let _ = scraper.extract_emails_from_text(&"@".repeat(10_000));
}

#[test]
fn fuzz_url_validation_no_panic() {
    // Random strings fed to validate_url must never panic.
    for _ in 0..5_000 {
        let input = random_ascii(rand::thread_rng().gen_range(0..300));
        let _ = WebScraper::validate_url(&input);
    }
    // Edge cases
    assert!(!WebScraper::validate_url(""));
    assert!(!WebScraper::validate_url("\0\0\0"));
    assert!(WebScraper::validate_url("https://example.com"));
    assert!(!WebScraper::validate_url("ftp://example.com"));

    // Unicode URLs
    for _ in 0..1_000 {
        let input = random_unicode(rand::thread_rng().gen_range(0..200));
        let _ = WebScraper::validate_url(&input);
    }
}

#[test]
fn fuzz_categorization_always_returns() {
    // InboxManager::categorize_message must always return a valid category.
    let inbox = InboxManager::new();
    let valid_categories = [
        MessageCategory::Lead,
        MessageCategory::Customer,
        MessageCategory::Support,
        MessageCategory::Spam,
        MessageCategory::Other,
    ];
    let mut rng = rand::thread_rng();
    for _ in 0..5_000 {
        let from = random_email();
        let subject = random_unicode(rng.gen_range(0..200));
        let msg = inbox.categorize_message(from, subject);
        assert!(
            valid_categories.contains(&msg.category),
            "Invalid category: {:?}",
            msg.category
        );
        assert!(!msg.id.is_nil(), "Message ID should not be nil");
    }
    // Edge cases
    let msg = inbox.categorize_message(String::new(), String::new());
    assert!(valid_categories.contains(&msg.category));
}
