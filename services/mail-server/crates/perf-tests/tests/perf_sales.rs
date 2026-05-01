//! Sales autopilot performance tests.

use std::time::{Duration, Instant};

use sales_autopilot::crm::CrmService;
use sales_autopilot::inbox::InboxManager;
use sales_autopilot::scrapers::WebScraper;

#[test]
fn test_lead_scoring_throughput() {
    let iterations = 100_000;

    let start = Instant::now();
    for i in 0..iterations {
        let engagement = (i % 100) as f64 / 100.0;
        let company_size = ((i + 33) % 100) as f64 / 100.0;
        let recency = ((i + 67) % 100) as f64 / 100.0;
        let _ = CrmService::score_lead(engagement, company_size, recency);
    }
    let elapsed = start.elapsed();

    println!(
        "Lead scoring throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "100,000 lead scorings took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_email_extraction_throughput() {
    let iterations = 10_000;
    let scraper = WebScraper::new();

    let texts = [
        "Contact us at sales@acme.com or support@acme.com for more info.",
        "Reach out to john.doe@example.org — we'd love to hear from you!",
        "No emails in this text, just plain content about our products.",
        "Multiple: a@b.com, c@d.org, e@f.io, test+tag@domain.co.uk end.",
        "Email hidden in HTML: <a href=\"mailto:hidden@test.com\">click</a>",
        "Large block of text with one email buried deep inside. The contact for \
         the engineering team is eng-lead@startup.dev and that's all.",
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let text = texts[i % texts.len()];
        let _ = scraper.extract_emails_from_text(text);
    }
    let elapsed = start.elapsed();

    println!(
        "Email extraction throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "10,000 email extractions took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_message_categorization_throughput() {
    let iterations = 100_000;
    let inbox = InboxManager::new();

    let messages: Vec<(&str, &str)> = vec![
        ("noreply@spam.com", "Buy viagra now lottery winner"),
        (
            "support@acme.com",
            "Re: Support ticket #1234 — issue resolved",
        ),
        ("jane@prospect.io", "Interested in a demo of your platform"),
        (
            "billing@vendor.com",
            "Invoice #INV-2025 — payment confirmation",
        ),
        ("ceo@bigcorp.com", "Partnership opportunity discussion"),
        ("alerts@monitoring.io", "Server health check passed"),
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let (from, subject) = messages[i % messages.len()];
        let _ = inbox.categorize_message(from.to_string(), subject.to_string());
    }
    let elapsed = start.elapsed();

    println!(
        "Message categorization throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "100,000 categorizations took {:?}, expected < 1s",
        elapsed
    );
}
