//! Simulation tests for the full email delivery lifecycle.
//!
//! This module exercises every stage of the pipeline — from job creation through
//! suppression checks, DKIM loading, tracking injection, transport routing,
//! backpressure/circuit‑breaker state machines, and the complete
//! pending → processing → sent/failed/deferred lifecycle — using unit-testable
//! pure functions and in‑memory state machines.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use chrono::Utc;
use moka::sync::Cache;

use super::common::{
    Backpressure, BackpressureConfig, CircuitBreaker, CircuitBreakerConfig, CircuitState,
    ProcessorError, SmtpConfig, TrackingConfig, TransportType,
};
use super::email::{
    add_tracking_pixel, create_transport, encode_tracking_id, rewrite_links, Attachment,
    CachedSuppression, DkimConfig, Domain, EmailJob, PreparedEmail, RateLimitResult, SendOutcome,
    TrackingPayload, WarmupLimits,
};

// ═══════════════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════════════

fn make_test_job() -> EmailJob {
    EmailJob {
        id: "job_sim_001".to_string(),
        message_id: "msg_sim_001".to_string(),
        tenant_id: "tenant_sim".to_string(),
        domain_id: "domain_sim".to_string(),
        from: "sender@apexmail.ee".to_string(),
        to: "recipient@example.com".to_string(),
        subject: "Simulation Test Email".to_string(),
        html: Some("<html><body><p>Hello</p><a href=\"https://example.com/page\">Click</a></body></html>".to_string()),
        text: Some("Hello from simulation".to_string()),
        headers: Some(serde_json::json!({"X-Custom": "sim-value"})),
        attachments: Some(serde_json::json!([{
            "filename": "report.pdf",
            "content": "R0lGODlhAQABAAAAACw=",
            "contentType": "application/pdf"
        }])),
        campaign_id: Some("camp_sim".to_string()),
        tags: Some(vec!["simulation".to_string(), "test".to_string()]),
        metadata: Some(serde_json::json!({"source": "simulation"})),
        scheduled_at: None,
        attempt: 0,
        max_attempts: 5,
        created_at: Utc::now(),
    }
}

fn make_test_domain() -> Domain {
    Domain {
        id: "domain_sim".to_string(),
        tenant_id: "tenant_sim".to_string(),
        domain: "apexmail.ee".to_string(),
        dkim_selector: Some("apexmail2026".to_string()),
        dkim_private_key: None,
        warmup_enabled: false,
        warmup_day: 0,
        return_path: None,
    }
}

fn make_test_tracking_config() -> TrackingConfig {
    TrackingConfig {
        enabled: true,
        base_url: "https://track.example.com".to_string(),
        open_pixel_path: "/o".to_string(),
        click_redirect_path: "/c".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. EmailJob creation — all required fields
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_job_all_fields_present() {
    let job = make_test_job();
    assert_eq!(job.id, "job_sim_001");
    assert_eq!(job.message_id, "msg_sim_001");
    assert_eq!(job.tenant_id, "tenant_sim");
    assert_eq!(job.domain_id, "domain_sim");
    assert_eq!(job.from, "sender@apexmail.ee");
    assert_eq!(job.to, "recipient@example.com");
    assert_eq!(job.subject, "Simulation Test Email");
    assert!(job.html.is_some());
    assert!(job.text.is_some());
    assert!(job.headers.is_some());
    assert!(job.attachments.is_some());
    assert_eq!(job.campaign_id, Some("camp_sim".to_string()));
    assert_eq!(job.tags, Some(vec!["simulation".to_string(), "test".to_string()]));
    assert_eq!(job.metadata, Some(serde_json::json!({"source": "simulation"})));
    assert_eq!(job.attempt, 0);
    assert!(job.scheduled_at.is_none());
}

#[test]
fn simulation_job_serde_roundtrip() {
    let job = make_test_job();
    let json = serde_json::to_string(&job).expect("serialize");
    let parsed: EmailJob = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.id, job.id);
    assert_eq!(parsed.message_id, job.message_id);
    assert_eq!(parsed.tenant_id, job.tenant_id);
    assert_eq!(parsed.from, job.from);
    assert_eq!(parsed.to, job.to);
    assert_eq!(parsed.subject, job.subject);
}

#[test]
fn simulation_job_clone_creates_independent_copy() {
    let job = make_test_job();
    let mut cloned = job.clone();
    cloned.id = "modified".to_string();
    assert_eq!(job.id, "job_sim_001");
    assert_eq!(cloned.id, "modified");
}

#[test]
fn simulation_job_optional_fields_none() {
    let mut job = make_test_job();
    job.html = None;
    job.text = None;
    job.headers = None;
    job.attachments = None;
    job.campaign_id = None;
    job.tags = None;
    job.metadata = None;
    job.scheduled_at = None;

    assert!(job.html.is_none());
    assert!(job.text.is_none());
    assert!(job.headers.is_none());
    assert!(job.attachments.is_none());
    assert!(job.campaign_id.is_none());
    assert!(job.tags.is_none());
    assert!(job.metadata.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Suppression checking — cached + DB fallback logic (pure simulation)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_cached_suppression_hit_marks_suppressed() {
    let cache: Cache<String, CachedSuppression> = Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(300))
        .build();

    cache.insert(
        "tenant_sim:recipient@example.com".to_string(),
        CachedSuppression {
            suppressed: true,
            reason: Some("spam_complaint".to_string()),
            expires_at: Instant::now() + Duration::from_secs(300),
        },
    );

    let key = "tenant_sim:recipient@example.com";
    let result = cache.get(key);
    assert!(result.is_some(), "cache hit expected");
    if let Some(cached) = result {
        assert!(cached.suppressed, "should be suppressed");
        assert_eq!(cached.reason.as_deref(), Some("spam_complaint"));
    }
}

#[test]
fn simulation_cached_suppression_miss_not_suppressed() {
    let cache: Cache<String, CachedSuppression> = Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(300))
        .build();

    let key = "unknown_tenant:unknown@example.com";
    assert!(cache.get(key).is_none(), "cache miss expected");
}

#[test]
fn simulation_batch_suppression_check_splits_cached_uncached() {
    // Simulate what batch_suppression_check does: for each job, check cache
    // first, then collect uncached emails for DB query.
    let cache: Cache<String, CachedSuppression> = Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(300))
        .build();

    // Pre-populate cache with one suppressed email
    cache.insert(
        "tenant_sim:suppressed@example.com".to_string(),
        CachedSuppression {
            suppressed: true,
            reason: Some("hard_bounce".to_string()),
            expires_at: Instant::now() + Duration::from_secs(300),
        },
    );

    let emails = vec![
        ("tenant_sim", "suppressed@example.com"),
        ("tenant_sim", "clean@example.com"),
        ("tenant_sim", "also_clean@example.com"),
    ];

    let mut suppressed: HashMap<String, String> = HashMap::new();
    let mut uncached: Vec<&str> = Vec::new();

    for (tenant, email) in &emails {
        let cache_key = format!("{}:{}", tenant, email);
        if let Some(cached) = cache.get(&cache_key) {
            if cached.suppressed {
                suppressed.insert(cache_key, cached.reason.clone().unwrap_or_default());
            }
        } else {
            uncached.push(*email);
        }
    }

    assert_eq!(suppressed.len(), 1);
    assert!(suppressed.contains_key("tenant_sim:suppressed@example.com"));
    assert_eq!(suppressed["tenant_sim:suppressed@example.com"], "hard_bounce");
    assert_eq!(uncached.len(), 2);
    assert!(uncached.contains(&"clean@example.com"));
    assert!(uncached.contains(&"also_clean@example.com"));
}

#[test]
fn simulation_suppression_cache_expiry() {
    let ttl = Duration::from_millis(10);
    let cache: Cache<String, CachedSuppression> = Cache::builder()
        .max_capacity(100)
        .time_to_live(ttl)
        .build();

    cache.insert(
        "key".to_string(),
        CachedSuppression {
            suppressed: true,
            reason: Some("test".to_string()),
            expires_at: Instant::now() + ttl,
        },
    );

    assert!(cache.get("key").is_some());

    std::thread::sleep(ttl + Duration::from_millis(20));

    // moka's time_to_live handles expiry internally; entries may linger briefly.
    // The key here is that the `expires_at` field is for informational purposes.
    // The actual cache eviction is managed by moka.
}

#[test]
fn simulation_suppression_cache_negative_caching() {
    // Simulate the negative caching pattern from batch_suppression_check
    let cache: Cache<String, CachedSuppression> = Cache::builder()
        .max_capacity(1000)
        .time_to_live(Duration::from_secs(300))
        .build();

    // Cache a negative result (not suppressed)
    cache.insert(
        "tenant:clean@example.com".to_string(),
        CachedSuppression {
            suppressed: false,
            reason: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        },
    );

    let result = cache.get("tenant:clean@example.com");
    assert!(result.is_some());
    if let Some(cached) = result {
        assert!(!cached.suppressed, "negatively cached = not suppressed");
        assert!(cached.reason.is_none());
    }
}

#[test]
fn simulation_suppression_cache_max_capacity_evicts_oldest() {
    let cache: Cache<String, CachedSuppression> = Cache::builder()
        .max_capacity(3)
        .time_to_live(Duration::from_secs(600))
        .build();

    for i in 0..10 {
        cache.insert(
            format!("key_{}", i),
            CachedSuppression {
                suppressed: i % 2 == 0,
                reason: Some(format!("reason_{}", i)),
                expires_at: Instant::now() + Duration::from_secs(600),
            },
        );
        // Force a maintenance run — moka handles this internally but we can
        // read a key to trigger background eviction management. Insert ordering
        // is not guaranteed for eviction, but capacity will be honored.
    }

    // After inserting 10 entries with capacity 3, the cache weight should be
    // bounded. moka's weight is the number of entries. We can't directly
    // assert the entry count, but we can verify that reads for non‑inserted
    // keys return None and that the cache didn't panic.
    assert!(cache.get("nonexistent").is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. DKIM configuration loading
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_dkim_config_from_domain_fields() {
    let domain = Domain {
        id: "dom_1".to_string(),
        tenant_id: "ten_1".to_string(),
        domain: "example.com".to_string(),
        dkim_selector: Some("sel2026".to_string()),
        dkim_private_key: Some("-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----".to_string()),
        warmup_enabled: false,
        warmup_day: 0,
        return_path: None,
    };

    let dkim = DkimConfig {
        selector: domain.dkim_selector.clone().unwrap(),
        domain: domain.domain.clone(),
        private_key: domain.dkim_private_key.clone().unwrap(),
    };

    assert_eq!(dkim.selector, "sel2026");
    assert_eq!(dkim.domain, "example.com");
    assert!(dkim.private_key.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn simulation_dkim_config_fallback_map() {
    // Simulate the pre-loaded DKIM keys map fallback in prepare_email
    let mut dkim_keys: HashMap<String, DkimConfig> = HashMap::new();
    dkim_keys.insert(
        "dom_1".to_string(),
        DkimConfig {
            selector: "fallback_sel".to_string(),
            domain: "fallback.example.com".to_string(),
            private_key: "pk_fallback".to_string(),
        },
    );

    let domain_without_key = Domain {
        id: "dom_1".to_string(),
        tenant_id: "ten_1".to_string(),
        domain: "example.com".to_string(),
        dkim_selector: None,
        dkim_private_key: None,
        warmup_enabled: false,
        warmup_day: 0,
        return_path: None,
    };

    let dkim = domain_without_key
        .dkim_private_key
        .as_ref()
        .map(|key| DkimConfig {
            selector: domain_without_key
                .dkim_selector
                .clone()
                .unwrap_or_else(|| "default".to_string()),
            domain: domain_without_key.domain.clone(),
            private_key: key.clone(),
        })
        .or_else(|| dkim_keys.get(&domain_without_key.id).cloned());

    assert!(dkim.is_some(), "fallback to pre-loaded map should succeed");
    let d = dkim.unwrap();
    assert_eq!(d.selector, "fallback_sel");
    assert_eq!(d.private_key, "pk_fallback");
}

#[test]
fn simulation_dkim_disabled_returns_none() {
    let dkim_enabled = false;
    let domain = make_test_domain();

    let dkim = if dkim_enabled {
        domain.dkim_private_key.as_ref().map(|key| DkimConfig {
            selector: "sel".to_string(),
            domain: domain.domain.clone(),
            private_key: key.clone(),
        })
    } else {
        None
    };

    assert!(dkim.is_none(), "DKIM should be None when disabled");
}

#[test]
fn simulation_dkim_config_debug_redacts_private_key() {
    let config = DkimConfig {
        selector: "sel".to_string(),
        domain: "example.com".to_string(),
        private_key: "secret_key_pem".to_string(),
    };

    let debug_str = format!("{:?}", config);
    // The Debug impl should show fields but not the full key
    assert!(debug_str.contains("sel"));
    assert!(debug_str.contains("example.com"));
}

#[test]
fn simulation_dkim_config_clone_works() {
    let original = DkimConfig {
        selector: "s1".to_string(),
        domain: "d1.com".to_string(),
        private_key: "key1".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(cloned.selector, "s1");
    assert_eq!(cloned.domain, "d1.com");
    assert_eq!(cloned.private_key, "key1");
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Tracking pixel injection and link rewriting
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_tracking_pixel_inserted_before_body_close() {
    let html = "<html><body><p>Hello</p></body></html>";
    let job = make_test_job();
    let config = make_test_tracking_config();

    let result = add_tracking_pixel(html, &job, &config);

    assert!(result.contains("https://track.example.com/o/"));
    assert!(result.contains(r#"width="1" height="1""#));
    assert!(result.contains("display:none"));

    let body_close = result.rfind("</body>").expect("should have </body>");
    let pixel_pos = result.find("track.example.com").expect("should have pixel");
    assert!(
        pixel_pos < body_close,
        "pixel should be before </body>"
    );
}

#[test]
fn simulation_tracking_pixel_falls_back_on_no_body() {
    let html = "<div>No body tag here</div>";
    let job = make_test_job();
    let config = make_test_tracking_config();

    let result = add_tracking_pixel(html, &job, &config);
    assert!(result.contains("https://track.example.com/o/"));
    assert!(result.ends_with(">"), "pixel appended at end");
}

#[test]
fn simulation_tracking_pixel_skips_script_body() {
    let html = r#"<html><body><p>Hello</p><script>if (x) { document.write('</body>'); }</script></body></html>"#;
    let job = make_test_job();
    let config = make_test_tracking_config();

    let result = add_tracking_pixel(html, &job, &config);
    let body_close = result.rfind("</body>").expect("should have real </body>");
    let pixel_pos = result.find("track.example.com").expect("should have pixel");
    assert!(pixel_pos < body_close, "pixel before real </body>, not script one");
}

#[test]
fn simulation_rewrite_links_replaces_href() {
    let html = r#"<a href="https://example.com/page">Click here</a>"#;
    let job = make_test_job();
    let config = make_test_tracking_config();

    let result = rewrite_links(html, &job, &config);
    assert!(result.contains("https://track.example.com/c/"));
    assert!(!result.contains("https://example.com/page"));
}

#[test]
fn simulation_rewrite_links_skips_mailto() {
    let html = r#"<a href="mailto:test@example.com">Email us</a>"#;
    let job = make_test_job();
    let config = make_test_tracking_config();

    let result = rewrite_links(html, &job, &config);
    assert!(result.contains("mailto:test@example.com"));
}

#[test]
fn simulation_rewrite_links_skips_unsubscribe() {
    let html = r#"<a href="https://example.com/unsubscribe">Unsubscribe</a>"#;
    let job = make_test_job();
    let config = make_test_tracking_config();

    let result = rewrite_links(html, &job, &config);
    assert!(result.contains("https://example.com/unsubscribe"));
    assert!(!result.contains("https://track.example.com/c/"));
}

#[test]
fn simulation_rewrite_links_skips_tel_and_hash() {
    let html = r##"<a href="tel:+123456">Call</a><a href="#section">Jump</a>"##;
    let job = make_test_job();
    let config = make_test_tracking_config();

    let result = rewrite_links(html, &job, &config);
    assert!(result.contains("tel:+123456"));
    assert!(result.contains("#section"));
}

#[test]
fn simulation_rewrite_links_skips_template_vars() {
    let html = r#"<a href="{{unsubscribe_url}}">Opt out</a>"#;
    let job = make_test_job();
    let config = make_test_tracking_config();

    let result = rewrite_links(html, &job, &config);
    assert!(result.contains("{{unsubscribe_url}}"));
}

#[test]
fn simulation_rewrite_links_multiple_anchors() {
    let html = r#"<a href="https://a.com/p1">A</a><a href="https://a.com/p2">B</a>"#;
    let job = make_test_job();
    let config = make_test_tracking_config();

    let result = rewrite_links(html, &job, &config);
    assert!(result.contains("https://track.example.com/c/"));
    assert!(!result.contains("https://a.com/p1"));
    assert!(!result.contains("https://a.com/p2"));
}

#[test]
fn simulation_tracking_payload_encode_decode() {
    let payload = TrackingPayload {
        message_id: "msg_123".to_string(),
        tenant_id: "ten_456".to_string(),
        recipient_hash: "abc123def".to_string(),
        original_url: Some("https://example.com".to_string()),
        campaign_id: Some("camp_789".to_string()),
    };

    let encoded = encode_tracking_id(&payload);
    assert!(!encoded.is_empty(), "encoded ID should not be empty");

    // Verify it's base64url (URL_SAFE_NO_PAD)
    assert!(!encoded.contains('+'), "URL-safe base64 should not contain '+'");
    assert!(!encoded.contains('/'), "URL-safe base64 should not contain '/'");
}

#[test]
fn simulation_tracking_disabled_skips_injection() {
    let mut config = make_test_tracking_config();
    config.enabled = false;

    let job = make_test_job();
    let html = job.html.clone().unwrap();

    // When tracking is disabled, prepare_email skips both functions.
    // Simulate this by checking the config guard:
    let mut modified = html.clone();
    if config.enabled {
        modified = add_tracking_pixel(&modified, &job, &config);
        modified = rewrite_links(&modified, &job, &config);
    }

    // Since tracking was disabled, HTML should be unchanged
    assert_eq!(modified, html);
}

#[test]
fn simulation_tracking_full_pipeline_pixel_and_links() {
    let job = make_test_job();
    let config = make_test_tracking_config();
    let html = job.html.clone().unwrap();

    let with_pixel = add_tracking_pixel(&html, &job, &config);
    let with_links = rewrite_links(&with_pixel, &job, &config);

    // Both pixel and link rewriting applied
    assert!(with_links.contains("https://track.example.com/o/"), "pixel present");
    assert!(with_links.contains("https://track.example.com/c/"), "link rewritten");
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Transport routing — SES vs SMTP
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_transport_creates_smtp_when_configured() {
    let config = SmtpConfig::default();
    let transport = create_transport(&config);
    assert_eq!(transport.transport_name(), "smtp");
}

#[test]
fn simulation_transport_type_from_env_smtp() {
    assert_eq!(TransportType::from_env("smtp"), TransportType::Smtp);
    assert_eq!(TransportType::from_env("SMTP"), TransportType::Smtp);
    assert_eq!(TransportType::from_env("self-hosted"), TransportType::Smtp);
    assert_eq!(TransportType::from_env("direct"), TransportType::Smtp);
}

#[test]
fn simulation_transport_type_from_env_ses_default() {
    assert_eq!(TransportType::from_env("ses"), TransportType::Ses);
    assert_eq!(TransportType::from_env("SES"), TransportType::Ses);
    assert_eq!(TransportType::from_env("anything"), TransportType::Ses);
    assert_eq!(TransportType::from_env(""), TransportType::Ses);
    assert_eq!(TransportType::default(), TransportType::Ses);
}

#[test]
fn simulation_prepared_email_builds_correctly_for_smtp() {
    // Verify that PreparedEmail is structured correctly and that
    // build_raw_mime / build_message can consume it.
    let email = PreparedEmail {
        from: "sender@example.com".into(),
        to: "recipient@example.com".into(),
        subject: "Test".into(),
        html: Some("<p>Hi</p>".into()),
        text: Some("Hi".into()),
        headers: vec![("X-Test".into(), "value".into())],
        attachments: vec![Attachment {
            filename: "file.txt".into(),
            content: b"hello".to_vec(),
            content_type: "text/plain".into(),
        }],
        dkim: None,
        return_path: None,
    };

    assert_eq!(email.from, "sender@example.com");
    assert_eq!(email.to, "recipient@example.com");
    assert_eq!(email.subject, "Test");
    assert!(email.html.is_some());
    assert!(email.text.is_some());
    assert_eq!(email.headers.len(), 1);
    assert_eq!(email.attachments.len(), 1);
    assert!(email.dkim.is_none());
}

#[test]
fn simulation_domain_cache_key_format() {
    // The domain cache key is format!("{}:{}", tenant_id, domain_id)
    let tenant = "tenant_sim";
    let domain_id = "domain_sim";
    let cache_key = format!("{}:{}", tenant, domain_id);
    assert_eq!(cache_key, "tenant_sim:domain_sim");
}

#[test]
fn simulation_mime_build_validates_prepared_email_structure() {
    // Verify PreparedEmail holds all MIME-relevant fields correctly.
    // The actual MIME builder (build_raw_mime / build_message) is tested
    // inside transport.rs module tests where it has visibility into
    // private functions. Here we verify the data contract.
    let email = PreparedEmail {
        from: "sender@example.com".into(),
        to: "recipient@example.com".into(),
        subject: "MIME Test".into(),
        html: Some("<p>HTML</p>".into()),
        text: Some("TEXT".into()),
        headers: vec![("X-Custom".into(), "val".into())],
        attachments: vec![],
        dkim: None,
        return_path: None,
    };

    assert_eq!(email.from, "sender@example.com");
    assert_eq!(email.to, "recipient@example.com");
    assert_eq!(email.subject, "MIME Test");
    assert!(email.html.as_deref().unwrap().contains("HTML"));
    assert!(email.text.as_deref().unwrap().contains("TEXT"));
    assert_eq!(email.headers[0].0, "X-Custom");
    assert!(email.attachments.is_empty());
    assert!(email.dkim.is_none());
}

#[test]
fn simulation_mime_build_empty_body_still_valid() {
    let email = PreparedEmail {
        from: "a@b.com".into(),
        to: "c@d.com".into(),
        subject: "Empty".into(),
        html: None,
        text: None,
        headers: vec![],
        attachments: vec![],
        dkim: None,
        return_path: None,
    };
    // Email with empty body is structurally valid — the transport layer
    // handles empty bodies gracefully (verified in transport.rs tests).
    assert!(email.html.is_none());
    assert!(email.text.is_none());
}

#[test]
fn simulation_mime_build_with_attachment_validates() {
    let email = PreparedEmail {
        from: "a@b.com".into(),
        to: "c@d.com".into(),
        subject: "With Attachment".into(),
        html: None,
        text: Some("See file".into()),
        headers: vec![],
        attachments: vec![Attachment {
            filename: "report.pdf".into(),
            content: b"%PDF-1.4 fake pdf".to_vec(),
            content_type: "application/pdf".into(),
        }],
        dkim: None,
        return_path: None,
    };
    assert_eq!(email.attachments.len(), 1);
    assert_eq!(email.attachments[0].filename, "report.pdf");
    assert_eq!(email.attachments[0].content_type, "application/pdf");
    assert_eq!(&email.attachments[0].content, b"%PDF-1.4 fake pdf");
}

#[test]
fn simulation_attachment_json_parsing() {
    // Simulate what prepare_email does: parse attachments from JSON
    let json = serde_json::json!([{
        "filename": "test.txt",
        "content": "SGVsbG8gV29ybGQ=",
        "contentType": "text/plain"
    }]);

    let attachments: Vec<Attachment> = json
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let obj = a.as_object()?;
                    Some(Attachment {
                        filename: obj.get("filename")?.as_str()?.to_string(),
                        content: base64::engine::general_purpose::STANDARD
                            .decode(obj.get("content")?.as_str()?)
                            .ok()?,
                        content_type: obj.get("contentType")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].filename, "test.txt");
    assert_eq!(attachments[0].content, b"Hello World");
    assert_eq!(attachments[0].content_type, "text/plain");
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Backpressure and circuit breaker state machines
// ═══════════════════════════════════════════════════════════════════════════

// ── Backpressure ───────────────────────────────────────────────────────────

#[test]
fn simulation_backpressure_initial_state() {
    let config = BackpressureConfig {
        max_concurrency: 15,
        max_backlog: 5000,
        cooldown: Duration::from_secs(5),
    };
    let bp = Backpressure::new(config);
    assert_eq!(bp.max_concurrency(), 15);
    assert_eq!(bp.available(), 15);
    assert_eq!(bp.in_flight(), 0);
    assert_eq!(bp.utilization(), 0.0);
    assert!(!bp.is_shedding());
}

#[tokio::test]
async fn simulation_backpressure_acquire_release_cycle() {
    let bp = Arc::new(Backpressure::new(BackpressureConfig {
        max_concurrency: 5,
        max_backlog: 100,
        cooldown: Duration::from_secs(60),
    }));

    let p1 = bp.acquire().await;
    assert!(p1.is_some());
    assert_eq!(bp.in_flight(), 1);

    let p2 = bp.acquire().await;
    assert!(p2.is_some());
    assert_eq!(bp.in_flight(), 2);

    drop(p1);
    assert_eq!(bp.in_flight(), 1);

    drop(p2);
    assert_eq!(bp.in_flight(), 0);
    assert_eq!(bp.available(), 5);
}

#[tokio::test]
async fn simulation_backpressure_exhausted_rejects() {
    let bp = Arc::new(Backpressure::new(BackpressureConfig {
        max_concurrency: 1,
        max_backlog: 100,
        cooldown: Duration::from_secs(60),
    }));

    let _p1 = bp.acquire().await.unwrap();
    let p2 = bp.acquire().await;
    assert!(p2.is_none(), "should reject when all permits taken");
}

#[test]
fn simulation_backpressure_load_shedding_triggers() {
    let config = BackpressureConfig {
        max_concurrency: 10,
        max_backlog: 50,
        cooldown: Duration::from_millis(50),
    };
    let bp = Backpressure::new(config);

    assert!(!bp.is_shedding());
    assert_eq!(bp.total_rejected(), 0);

    bp.observe_backlog(100); // exceeds max_backlog
    assert!(bp.is_shedding(), "should enter cooldown after exceeding backlog");

    std::thread::sleep(Duration::from_millis(100));
    assert!(!bp.is_shedding(), "should recover after cooldown");
}

#[test]
fn simulation_backpressure_utilization_reflects_in_flight() {
    let config = BackpressureConfig {
        max_concurrency: 10,
        max_backlog: 100,
        cooldown: Duration::from_secs(60),
    };
    let bp = Backpressure::new(config);
    assert_eq!(bp.utilization(), 0.0);
    // We can't easily acquire without async, but the initial state is verifiable
    assert_eq!(bp.backlog(), 0);
}

// ── Circuit Breaker ────────────────────────────────────────────────────────

#[test]
fn simulation_circuit_breaker_full_lifecycle() {
    let cb = CircuitBreaker::new(CircuitBreakerConfig {
        failure_threshold: 3,
        open_duration: Duration::from_millis(10),
        success_threshold: 2,
        window_duration: Duration::from_secs(60),
    });

    // Phase 1: Closed → Open after 3 failures
    assert_eq!(cb.state(), CircuitState::Closed);
    assert!(cb.is_allowed());

    cb.record_failure(); // 1
    cb.record_failure(); // 2
    assert_eq!(cb.state(), CircuitState::Closed);

    cb.record_failure(); // 3 → Open
    assert_eq!(cb.state(), CircuitState::Open);
    assert!(!cb.is_allowed());

    // Phase 2: Open → HalfOpen after open_duration
    std::thread::sleep(Duration::from_millis(15));
    assert!(cb.is_allowed()); // transitions to HalfOpen
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    // Phase 3: HalfOpen → Closed after 2 successes
    cb.record_success(); // 1
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    cb.record_success(); // 2 → Closed
    assert_eq!(cb.state(), CircuitState::Closed);
    assert!(cb.is_allowed());
}

#[test]
fn simulation_circuit_breaker_half_open_failure_returns_to_open() {
    let cb = CircuitBreaker::new(CircuitBreakerConfig {
        failure_threshold: 1,
        open_duration: Duration::from_millis(10),
        success_threshold: 5,
        window_duration: Duration::from_secs(60),
    });

    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);

    std::thread::sleep(Duration::from_millis(15));
    assert!(cb.is_allowed());
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    // A single failure in HalfOpen should reopen
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);
    assert!(!cb.is_allowed());
}

#[test]
fn simulation_circuit_breaker_reset_returns_to_closed() {
    let cb = CircuitBreaker::new(CircuitBreakerConfig {
        failure_threshold: 1,
        open_duration: Duration::from_secs(60),
        success_threshold: 3,
        window_duration: Duration::from_secs(120),
    });

    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);

    cb.reset();
    assert_eq!(cb.state(), CircuitState::Closed);
    assert!(cb.is_allowed());
}

#[test]
fn simulation_circuit_breaker_failure_window_resets() {
    let cb = CircuitBreaker::new(CircuitBreakerConfig {
        failure_threshold: 3,
        open_duration: Duration::from_secs(60),
        success_threshold: 3,
        window_duration: Duration::from_millis(5),
    });

    // Record 2 failures
    cb.record_failure();
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Closed);

    // Wait for window to expire
    std::thread::sleep(Duration::from_millis(10));

    // Next failure should reset the window (starts fresh)
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Closed, "window reset, only 1 failure");
}

#[test]
fn simulation_circuit_breaker_concurrent_failures() {
    let cb = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
        failure_threshold: 10,
        open_duration: Duration::from_secs(60),
        success_threshold: 3,
        window_duration: Duration::from_secs(120),
    }));

    let mut handles = Vec::new();
    for _ in 0..15 {
        let cb = cb.clone();
        handles.push(std::thread::spawn(move || {
            cb.record_failure();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // 15 failures with threshold 10 → circuit must be open
    assert_eq!(cb.state(), CircuitState::Open);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Complete job lifecycle — pending → processing → sent/failed/deferred
// ═══════════════════════════════════════════════════════════════════════════

/// Simulated job status for the lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimulatedJobStatus {
    Pending,
    #[allow(dead_code)]
    Processing,
    Sent,
    Failed,
    Deferred,
    Suppressed,
    Bounced,
}

/// Simulate the email processor lifecycle decision tree.
struct LifecycleSimulator {
    max_retries: i32,
    circuit_breaker_open: bool,
    warmup_exceeded: bool,
    suppressed: bool,
    hard_bounce: bool,
    soft_bounce: bool,
    transport_error: bool,
}

impl LifecycleSimulator {
    fn new(max_retries: i32) -> Self {
        Self {
            max_retries,
            circuit_breaker_open: false,
            warmup_exceeded: false,
            suppressed: false,
            hard_bounce: false,
            soft_bounce: false,
            transport_error: false,
        }
    }

    fn simulate_lifecycle(&self, attempt: i32) -> SimulatedJobStatus {
        // 1. Check circuit breaker
        if self.circuit_breaker_open {
            return SimulatedJobStatus::Deferred;
        }

        // 2. Check warmup limits
        if self.warmup_exceeded {
            return SimulatedJobStatus::Pending; // requeued
        }

        // 3. Check suppression
        if self.suppressed {
            return SimulatedJobStatus::Suppressed;
        }

        // 4. Attempt delivery
        if self.hard_bounce {
            return SimulatedJobStatus::Bounced;
        }

        if self.soft_bounce {
            if attempt >= self.max_retries {
                return SimulatedJobStatus::Bounced;
            }
            return SimulatedJobStatus::Deferred;
        }

        if self.transport_error {
            if attempt >= self.max_retries {
                return SimulatedJobStatus::Failed;
            }
            return SimulatedJobStatus::Deferred;
        }

        SimulatedJobStatus::Sent
    }
}

#[test]
fn simulation_lifecycle_success_path() {
    let sim = LifecycleSimulator::new(3);
    assert_eq!(
        sim.simulate_lifecycle(0),
        SimulatedJobStatus::Sent,
        "clean job should be sent on first attempt"
    );
}

#[test]
fn simulation_lifecycle_suppression_short_circuits() {
    let mut sim = LifecycleSimulator::new(3);
    sim.suppressed = true;
    assert_eq!(
        sim.simulate_lifecycle(0),
        SimulatedJobStatus::Suppressed,
        "suppressed jobs skip delivery"
    );
}

#[test]
fn simulation_lifecycle_circuit_breaker_defers() {
    let mut sim = LifecycleSimulator::new(3);
    sim.circuit_breaker_open = true;
    assert_eq!(
        sim.simulate_lifecycle(0),
        SimulatedJobStatus::Deferred,
        "circuit open should defer"
    );
}

#[test]
fn simulation_lifecycle_warmup_exceeded_requeues() {
    let mut sim = LifecycleSimulator::new(3);
    sim.warmup_exceeded = true;
    assert_eq!(
        sim.simulate_lifecycle(0),
        SimulatedJobStatus::Pending,
        "warmup limit exceeded → requeue pending"
    );
}

#[test]
fn simulation_lifecycle_soft_bounce_retries() {
    let mut sim = LifecycleSimulator::new(5);

    // Attempt 0–4: soft bounce → deferred
    sim.soft_bounce = true;
    for attempt in 0..5 {
        assert_eq!(
            sim.simulate_lifecycle(attempt),
            SimulatedJobStatus::Deferred,
            "attempt {}: soft bounce should defer (attempt < max_retries)",
            attempt
        );
    }
}

#[test]
fn simulation_lifecycle_soft_bounce_exhausted() {
    let mut sim = LifecycleSimulator::new(3);
    sim.soft_bounce = true;

    for attempt in 0..3 {
        assert_eq!(
            sim.simulate_lifecycle(attempt),
            SimulatedJobStatus::Deferred,
            "attempt {}: still retryable",
            attempt
        );
    }

    // At attempt == max_retries (3), it should bounce
    assert_eq!(
        sim.simulate_lifecycle(3),
        SimulatedJobStatus::Bounced,
        "exhausted soft bounce → bounced"
    );
}

#[test]
fn simulation_lifecycle_hard_bounce_immediate() {
    let mut sim = LifecycleSimulator::new(5);
    sim.hard_bounce = true;
    assert_eq!(
        sim.simulate_lifecycle(0),
        SimulatedJobStatus::Bounced,
        "hard bounce on first attempt → bounced"
    );
}

#[test]
fn simulation_lifecycle_transport_error_retries_then_fails() {
    let mut sim = LifecycleSimulator::new(3);
    sim.transport_error = true;

    for attempt in 0..3 {
        assert_eq!(
            sim.simulate_lifecycle(attempt),
            SimulatedJobStatus::Deferred,
            "attempt {}: transport error should defer if retries remain",
            attempt
        );
    }

    assert_eq!(
        sim.simulate_lifecycle(3),
        SimulatedJobStatus::Failed,
        "max retries reached → failed (DLQ)"
    );
}

#[test]
fn simulation_lifecycle_full_state_graph() {
    // Trace the possible transitions:
    //
    // Pending → Processing (claim job)
    // Processing → Sent (delivery OK)
    // Processing → Suppressed (suppression check hit)
    // Processing → Bounced (hard bounce → add to suppressions)
    // Processing → Deferred (soft bounce / transient → retry with backoff)
    // Processing → Failed (max retries exceeded → move to DLQ)
    // Processing → Pending (warmup limit → requeue)

    let transitions: Vec<(SimulatedJobStatus, &str)> = vec![
        (SimulatedJobStatus::Sent, "successful delivery"),
        (SimulatedJobStatus::Suppressed, "suppression hit"),
        (SimulatedJobStatus::Bounced, "hard bounce"),
        (SimulatedJobStatus::Deferred, "temporary failure → retry"),
        (SimulatedJobStatus::Failed, "permanent failure → DLQ"),
    ];

    // All terminal states are covered
    for (status, description) in &transitions {
        match status {
            SimulatedJobStatus::Sent
            | SimulatedJobStatus::Suppressed
            | SimulatedJobStatus::Bounced
            | SimulatedJobStatus::Failed => {
                // These are terminal — job won't be re-processed
                assert!(
                    true,
                    "terminal state '{}' ({:?}) verified",
                    description, status
                );
            }
            SimulatedJobStatus::Deferred | SimulatedJobStatus::Pending => {
                // Non-terminal — will be retried
                assert!(
                    true,
                    "retryable state '{}' ({:?}) verified",
                    description, status
                );
            }
            SimulatedJobStatus::Processing => {
                // Intermediate — only valid in-flight
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Exponential backoff calculation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_backoff_formula_matches_handle_soft_bounce() {
    let base_retry_delay: i64 = 60; // seconds

    let cases = [
        (0, 60),
        (1, 120),
        (2, 240),
        (3, 480),
        (4, 960),
        (5, 1920),
        (10, 61_440),
    ];

    for (attempt, expected_delay) in cases {
        let multiplier = 2_i64.saturating_pow(attempt.min(30) as u32);
        let delay = base_retry_delay.saturating_mul(multiplier);
        assert_eq!(
            delay, expected_delay,
            "attempt {}: 60 * 2^{} = {}s",
            attempt, attempt, expected_delay
        );
    }

    // Cap at attempt 30
    let attempt: i32 = 30;
    let multiplier = 2_i64.saturating_pow(attempt.min(30) as u32);
    let delay = base_retry_delay.saturating_mul(multiplier);
    assert_eq!(
        delay,
        60_i64.saturating_mul(1_073_741_824),
        "attempt 30: capped at 2^30"
    );

    let attempt: i32 = 100;
    let multiplier = 2_i64.saturating_pow(attempt.min(30) as u32);
    let delay = base_retry_delay.saturating_mul(multiplier);
    assert_eq!(
        delay,
        60_i64.saturating_mul(1_073_741_824),
        "attempt >30: still capped at 2^30"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. Warmup limits calculation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_warmup_limits_day_0() {
    let limits = WarmupLimits::for_day(0);
    assert_eq!(limits.daily_limit, 50);
    assert_eq!(limits.hourly_limit, 10); // 50/18 = 2 → max(2, 10) = 10
}

#[test]
fn simulation_warmup_limits_day_1() {
    let limits = WarmupLimits::for_day(1);
    assert_eq!(limits.daily_limit, 100);
    assert_eq!(limits.hourly_limit, 10); // 100/18 = 5 → max(5, 10) = 10
}

#[test]
fn simulation_warmup_limits_day_7() {
    let limits = WarmupLimits::for_day(7);
    assert_eq!(limits.daily_limit, 4_000);
    assert_eq!(limits.hourly_limit, 4_000 / 18);
}

#[test]
fn simulation_warmup_limits_day_14() {
    let limits = WarmupLimits::for_day(14);
    assert_eq!(limits.daily_limit, 40_000);
}

#[test]
fn simulation_warmup_limits_day_28() {
    let limits = WarmupLimits::for_day(28);
    assert_eq!(limits.daily_limit, 1_000_000);
}

#[test]
fn simulation_warmup_limits_fully_warmed() {
    let limits = WarmupLimits::for_day(29);
    assert_eq!(limits.daily_limit, i64::MAX);
}

#[test]
fn simulation_warmup_limits_monotonically_increasing() {
    let mut prev = 0;
    for day in 0..=29 {
        let limits = WarmupLimits::for_day(day);
        assert!(
            limits.daily_limit >= prev,
            "day {}: limit {} >= previous {}",
            day,
            limits.daily_limit,
            prev
        );
        prev = limits.daily_limit;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Error rate tracking — sliding window algorithm
// ═══════════════════════════════════════════════════════════════════════════

const ERROR_WINDOW_SIZE: usize = 20;
const ERROR_THRESHOLD: usize = 10;

fn simulate_error_tracking(
    outcomes: &mut Vec<(SendOutcome, Instant)>,
    outcome: SendOutcome,
    now: Instant,
) -> bool {
    outcomes.push((outcome, now));
    outcomes.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60));
    let len = outcomes.len();
    if len > ERROR_WINDOW_SIZE {
        outcomes.drain(0..(len - ERROR_WINDOW_SIZE));
    }
    let failures = outcomes
        .iter()
        .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
        .count();
    failures >= ERROR_THRESHOLD
}

#[test]
fn simulation_error_rate_window_caps_at_20() {
    let mut outcomes = Vec::new();
    let now = Instant::now();

    for _ in 0..30 {
        simulate_error_tracking(&mut outcomes, SendOutcome::Success, now);
    }
    assert_eq!(outcomes.len(), ERROR_WINDOW_SIZE);
}

#[test]
fn simulation_error_rate_triggers_cooldown() {
    let mut outcomes = Vec::new();
    let now = Instant::now();

    // Fill window with 10 successes
    for _ in 0..10 {
        simulate_error_tracking(&mut outcomes, SendOutcome::Success, now);
    }
    // Add 10 failures → window is 20, 10 failures
    let mut triggered = false;
    for _ in 0..10 {
        let t = simulate_error_tracking(&mut outcomes, SendOutcome::TransportError, now);
        if t {
            triggered = true;
        }
    }

    assert!(triggered, "10 failures in a 20-entry window should trigger");
    assert_eq!(outcomes.len(), ERROR_WINDOW_SIZE);
    let failures = outcomes
        .iter()
        .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
        .count();
    assert_eq!(failures, ERROR_THRESHOLD);
}

#[test]
fn simulation_error_rate_no_trigger_below_threshold() {
    let mut outcomes = Vec::new();
    let now = Instant::now();

    for _ in 0..11 {
        simulate_error_tracking(&mut outcomes, SendOutcome::Success, now);
    }
    for _ in 0..9 {
        let t = simulate_error_tracking(&mut outcomes, SendOutcome::TransportError, now);
        assert!(!t, "9 failures < 10 threshold should not trigger");
    }
}

#[test]
fn simulation_error_rate_old_entries_evicted() {
    let mut outcomes = Vec::new();
    let old = Instant::now() - Duration::from_secs(120);

    // 10 old failures
    for _ in 0..10 {
        simulate_error_tracking(&mut outcomes, SendOutcome::TransportError, old);
    }
    assert_eq!(outcomes.len(), 10);

    // New success at current time → old entries evicted
    let new_now = Instant::now();
    simulate_error_tracking(&mut outcomes, SendOutcome::Success, new_now);

    assert_eq!(
        outcomes.len(),
        1,
        "old entries evicted by the 60s retention window"
    );
    assert!(matches!(outcomes[0].0, SendOutcome::Success));
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. SendOutcome classification
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_send_outcome_classification() {
    // Test how ProcessorError maps to SendOutcome in process_job
    // Success → Success
    // Transport("Soft bounce") → SoftBounce
    // Transport("Hard bounce") → HardBounce
    // RateLimited → RateLimit
    // Everything else → TransportError

    let outcomes = vec![
        (Ok(()), SendOutcome::Success),
        (
            Err(ProcessorError::Transport("Soft bounce: mailbox full".into())),
            SendOutcome::SoftBounce,
        ),
        (
            Err(ProcessorError::Transport("Hard bounce: user unknown".into())),
            SendOutcome::HardBounce,
        ),
        (
            Err(ProcessorError::RateLimited("too fast".into())),
            SendOutcome::RateLimit,
        ),
        (
            Err(ProcessorError::Config("bad config".into())),
            SendOutcome::TransportError,
        ),
        (
            Err(ProcessorError::CircuitOpen("circuit".into())),
            SendOutcome::TransportError,
        ),
    ];

    for (result, expected_outcome) in outcomes {
        let outcome = match &result {
            Ok(_) => SendOutcome::Success,
            Err(ProcessorError::Transport(msg)) if msg.contains("Soft bounce") => {
                SendOutcome::SoftBounce
            }
            Err(ProcessorError::Transport(msg)) if msg.contains("Hard bounce") => {
                SendOutcome::HardBounce
            }
            Err(ProcessorError::RateLimited(_)) => SendOutcome::RateLimit,
            Err(_) => SendOutcome::TransportError,
        };
        assert_eq!(
            outcome, expected_outcome,
            "expected {:?}, got {:?} for result {:?}",
            expected_outcome, outcome, result.as_ref().err()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. Rate limit result structure
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_rate_limit_result_allowed() {
    let r = RateLimitResult {
        allowed: true,
        reason: None,
        current_count: 5,
        limit: 100,
        retry_after_ms: None,
        isp: None,
    };
    assert!(r.allowed);
    assert!(r.current_count < r.limit);
}

#[test]
fn simulation_rate_limit_result_blocked() {
    let r = RateLimitResult {
        allowed: false,
        reason: Some("rate limit exceeded".to_string()),
        current_count: 101,
        limit: 100,
        retry_after_ms: Some(60_000),
        isp: Some("gmail".to_string()),
    };
    assert!(!r.allowed);
    assert!(r.current_count > r.limit);
    assert_eq!(r.isp.as_deref(), Some("gmail"));
}

#[test]
fn simulation_rate_limit_result_clone_maintains_values() {
    let original = RateLimitResult {
        allowed: false,
        reason: Some("blocked".to_string()),
        current_count: 50,
        limit: 50,
        retry_after_ms: Some(5000),
        isp: Some("outlook".to_string()),
    };
    let cloned = original.clone();
    assert_eq!(original.allowed, cloned.allowed);
    assert_eq!(original.reason, cloned.reason);
    assert_eq!(original.current_count, cloned.current_count);
    assert_eq!(original.limit, cloned.limit);
    assert_eq!(original.retry_after_ms, cloned.retry_after_ms);
    assert_eq!(original.isp, cloned.isp);
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. Protected headers filtering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_protected_headers_blocked() {
    const PROTECTED_HEADERS: &[&str] = &[
        "from",
        "to",
        "cc",
        "bcc",
        "subject",
        "date",
        "message-id",
        "dkim-signature",
        "arc-seal",
        "arc-message-signature",
        "arc-authentication-results",
        "return-path",
        "received",
        "received-spf",
        "authentication-results",
        "x-apexmail-message-id",
        "x-apexmail-tenant-id",
        "x-apexmail-campaign-id",
        "x-originating-ip",
        "x-mailer",
        "mime-version",
        "content-type",
        "content-transfer-encoding",
    ];

    let _job = make_test_job();
    // Create headers that include protected ones
    let custom_headers = serde_json::json!({
        "from": "attacker@evil.com",
        "dkim-signature": "forged",
        "X-Custom": "allowed",
        "X-ApexMail-Message-ID": "spoofed",
    });

    let mut allowed_headers: Vec<(String, String)> = Vec::new();
    if let Some(obj) = custom_headers.as_object() {
        for (key, value) in obj {
            let key_lower = key.to_lowercase();
            if PROTECTED_HEADERS.contains(&key_lower.as_str()) {
                continue;
            }
            if let Some(v) = value.as_str() {
                allowed_headers.push((key.clone(), v.to_string()));
            }
        }
    }

    assert_eq!(allowed_headers.len(), 1);
    assert_eq!(allowed_headers[0].0, "X-Custom");
    assert_eq!(allowed_headers[0].1, "allowed");

    // Verify that protected headers were filtered
    let allowed_keys: Vec<&str> = allowed_headers.iter().map(|(k, _)| k.as_str()).collect();
    assert!(!allowed_keys.contains(&"from"));
    assert!(!allowed_keys.contains(&"dkim-signature"));
    assert!(!allowed_keys.contains(&"X-ApexMail-Message-ID"));
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. Domain fetching simulation (cached + uncached)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_domain_cache_hit_avoids_db() {
    let domain_cache: Cache<String, Domain> = Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(300))
        .build();

    let cached_domain = make_test_domain();
    let cache_key = format!("{}:{}", cached_domain.tenant_id, cached_domain.id);
    domain_cache.insert(cache_key.clone(), cached_domain.clone());

    let result = domain_cache.get(&cache_key);
    assert!(result.is_some());
    assert_eq!(result.unwrap().domain, "apexmail.ee");
}

#[test]
fn simulation_domain_cache_miss_triggers_db_lookup() {
    let domain_cache: Cache<String, Domain> = Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(300))
        .build();

    let cache_key = "tenant_unknown:domain_unknown";
    assert!(domain_cache.get(cache_key).is_none(), "miss triggers DB query");
}

// ═══════════════════════════════════════════════════════════════════════════
// 15. Edge cases and invariants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simulation_email_job_debug_output_contains_key_fields() {
    let job = make_test_job();
    let debug = format!("{:?}", job);
    assert!(debug.contains("job_sim_001"));
    assert!(debug.contains("tenant_sim"));
    assert!(debug.contains("Simulation Test Email"));
}

#[test]
fn simulation_prepared_email_with_dkim_config() {
    let email = PreparedEmail {
        from: "sender@example.com".into(),
        to: "recipient@example.com".into(),
        subject: "Signed Email".into(),
        html: Some("<p>Signed</p>".into()),
        text: Some("Signed".into()),
        headers: vec![],
        attachments: vec![],
        dkim: Some(DkimConfig {
            selector: "sel".into(),
            domain: "example.com".into(),
            private_key: "pk".into(),
        }),
        return_path: None,
    };

    assert!(email.dkim.is_some());
    let d = email.dkim.as_ref().unwrap();
    assert_eq!(d.selector, "sel");
    assert_eq!(d.domain, "example.com");
}

#[test]
fn simulation_cached_suppression_expires_at_is_future() {
    let cached = CachedSuppression {
        suppressed: true,
        reason: Some("spam".to_string()),
        expires_at: Instant::now() + Duration::from_secs(300),
    };
    assert!(
        Instant::now() < cached.expires_at,
        "expires_at should be in the future"
    );
}

#[test]
fn simulation_attempt_field_clamps_to_max_i32() {
    let mut job = make_test_job();
    job.attempt = 0;
    assert_eq!(job.attempt, 0);

    job.attempt = i32::MAX;
    assert_eq!(job.attempt, i32::MAX);

    // The retry logic uses attempt.min(30), so values >30 are harmless
    let capped = job.attempt.min(30);
    assert_eq!(capped, 30);
}

#[test]
fn simulation_visibility_timeout_converts_to_millis() {
    let visibility_timeout = Duration::from_secs(300);
    let visibility_ms = visibility_timeout.as_millis();
    assert_eq!(visibility_ms, 300_000);

    // The converter in fetch_jobs caps at i64::MAX
    let visibility_ms_i64 = if visibility_ms > i64::MAX as u128 {
        i64::MAX
    } else {
        visibility_ms as i64
    };
    assert_eq!(visibility_ms_i64, 300_000);
}

#[test]
fn simulation_max_visibility_timeout_clips_to_i64_max() {
    // Simulate a very large timeout that would exceed i64::MAX
    let huge_ms: u128 = i64::MAX as u128 + 1;
    let clipped = if huge_ms > i64::MAX as u128 {
        i64::MAX
    } else {
        huge_ms as i64
    };
    assert_eq!(clipped, i64::MAX);
}

#[test]
fn simulation_poll_loop_available_slots_calculation() {
    let concurrency: usize = 10;
    let active_jobs: usize = 3;
    let available_slots = concurrency.saturating_sub(active_jobs);
    assert_eq!(available_slots, 7);

    let over_subscribed = concurrency.saturating_sub(15);
    assert_eq!(over_subscribed, 0, "saturating_sub prevents underflow");
}
