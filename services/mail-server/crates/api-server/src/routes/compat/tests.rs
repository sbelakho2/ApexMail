//! Contract + adversarial tests for the provider compatibility surface.
//!
//! Every test drives the REAL `build_app` router (so the provider-shaped
//! credential middleware, the canonical rate limiter and the canonical send
//! handlers all run) over a fresh canonical database, seeds a tenant with a
//! verified sender domain + consent records exactly like the canonical send
//! suites, and then asserts:
//!
//! * the provider-shaped SUCCESS response (status + body/headers);
//! * **that the canonical send path is what ran** — the `messages` row AND
//!   the per-recipient `email_queue` rows are read back and compared field by
//!   field against the provider payload's mapping (the queue-row spy: a
//!   mapping layer that bypassed or duplicated the canonical insert could not
//!   produce these rows);
//! * auth refusals in each provider's own error shape;
//! * validation parity — a suppressed recipient, an unverified sender domain
//!   and a missing subject are refused by the CANONICAL gates and rendered in
//!   the provider's shape, with nothing queued;
//! * the named refusals for fields this surface cannot honour (no silent
//!   drops), and the named `501` for Mailgun's `.mime` endpoint.

#![cfg(test)]

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use base64::Engine;
use sqlx::PgPool;
use tower::ServiceExt;

use super::{Provider, CATEGORY_HEADER};
use crate::app::build_app;
use crate::state::AppState;

// ─── Fixtures ──────────────────────────────────────────────────

struct Fixture {
    state: AppState,
    app: Router,
    pool: PgPool,
    tenant: String,
    key: String,
    domain: String,
}

/// A tenant with a verified sender domain, a `messages:send` key and consent
/// records for the recipients these tests submit to (sends default to the
/// canonical `marketing` category, whose consent gate is part of the parity
/// this suite asserts).
async fn fixture(suffix: &str) -> Option<Fixture> {
    let pool = crate::test_db::canonical_pool(suffix).await?;
    let tenant = apexmail_lib::id::generate_id("cmpt", 20);
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
         VALUES ($1, 'compat fixture', $2, 'free', 'active', NOW(), NOW())",
    )
    .bind(&tenant)
    .bind(format!("compat-{suffix}-{tenant}"))
    .execute(&pool)
    .await
    .expect("seed compat tenant");

    let domain = format!(
        "compat-{}.example.com",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified,
             dkim_selector, dkim_public_key, dkim_private_key)
         VALUES ($1::uuid, $2, $3, 'verified', true, true, true, 'test-selector', 'test-public-key', 'dkim:v1:test')",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&tenant)
    .bind(&domain)
    .execute(&pool)
    .await
    .expect("seed verified domain");

    for recipient in [
        "to@example.com",
        "to2@example.com",
        "cc@example.com",
        "bcc@example.com",
        "blocked@example.com",
        "good@example.com",
        "bad@example.com",
    ] {
        grant_marketing_consent(&pool, &tenant, recipient).await;
    }

    let key = crate::app::test_support::seed_api_key_for(&pool, &tenant, &["messages:send"]).await;
    let state = crate::app::test_support::test_state_over(pool.clone()).await;
    let app = build_app(state.clone());
    Some(Fixture {
        state,
        app,
        pool,
        tenant,
        key,
        domain,
    })
}

async fn grant_marketing_consent(pool: &PgPool, tenant_id: &str, recipient: &str) {
    sqlx::query(
        "INSERT INTO consent_records \
             (id, tenant_id, subscriber_id, email, consent_type, granted, granted_at, source) \
         VALUES ($1, $2, $3, $4, 'marketing', true, NOW(), 'form') \
         ON CONFLICT (tenant_id, subscriber_id, consent_type) DO UPDATE SET \
             granted = true, revoked_at = NULL, granted_at = NOW()",
    )
    .bind(format!(
        "cons-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..24]
    ))
    .bind(tenant_id)
    .bind(recipient)
    .bind(recipient)
    .execute(pool)
    .await
    .expect("grant marketing consent");
}

/// The provider-native credential header for a raw key.
fn auth_header(provider: Provider, key: &str) -> (String, String) {
    match provider {
        Provider::SendGrid | Provider::Resend => ("authorization".into(), format!("Bearer {key}")),
        Provider::Mailgun => (
            "authorization".into(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("api:{key}"))
            ),
        ),
        Provider::Postmark => ("x-postmark-server-token".into(), key.to_string()),
    }
}

/// One HTTP call through the real router.
async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(String, String)],
    content_type: &str,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", content_type);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let request = builder.body(Body::from(body)).expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, headers, bytes)
}

/// Provider-authenticated JSON POST.
async fn post_json(
    app: &Router,
    provider: Provider,
    key: &str,
    uri: &str,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let (name, value) = auth_header(provider, key);
    let (status, _headers, bytes) = call(
        app,
        Method::POST,
        uri,
        &[(name, value)],
        "application/json",
        body.to_string().into_bytes(),
    )
    .await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// The stored `messages` row, as the parity assertions read it.
#[derive(sqlx::FromRow)]
struct MessageRow {
    from_email: String,
    to_emails: serde_json::Value,
    cc_emails: Option<serde_json::Value>,
    bcc_emails: Option<serde_json::Value>,
    subject: String,
    html_body: Option<String>,
    text_body: Option<String>,
    tags: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
    headers: Option<serde_json::Value>,
    attachments: Option<serde_json::Value>,
    reply_to: Option<String>,
    message_category: String,
}

async fn message_row(pool: &PgPool, tenant: &str, id: &str) -> MessageRow {
    sqlx::query_as::<_, MessageRow>(
        "SELECT from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body,
                tags, metadata, headers, attachments, reply_to, message_category
         FROM messages WHERE tenant_id = $1 AND id = $2::uuid",
    )
    .bind(tenant)
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("the canonical send path must have persisted the message row")
}

async fn message_count(pool: &PgPool, tenant: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("count messages")
}

/// The per-recipient queue rows (the canonical fan-out), ordered by address.
/// Column types follow the canonical schema: `tags` is `TEXT[]`, the rest are
/// `jsonb`.
async fn queue_rows(
    pool: &PgPool,
    message_id: &str,
) -> Vec<(
    String,
    String,
    Option<String>,
    Option<String>,
    Option<Vec<String>>,
    Option<serde_json::Value>,
    Option<serde_json::Value>,
    Option<serde_json::Value>,
    String,
)> {
    sqlx::query_as(
        "SELECT \"to\", subject, html, text, tags, metadata, headers, attachments, message_category
         FROM email_queue WHERE message_id = $1::uuid ORDER BY \"to\"",
    )
    .bind(message_id)
    .fetch_all(pool)
    .await
    .expect("queue rows")
}

// ─── Auth: provider-shaped refusals, canonical identity ────────

/// Every surface refuses a MISSING credential in its own provider's shape,
/// and a VALID ApexMail key in that provider's own header authenticates the
/// canonical tenant (proved by a 202/200 send below).
#[tokio::test]
async fn missing_credentials_answer_in_each_providers_error_shape() {
    let Some(fixture) = fixture("compat_auth_missing").await else {
        return;
    };
    let app = &fixture.app;

    let (status, body) = post_json(
        app,
        Provider::SendGrid,
        "",
        "/v3/mail/send",
        &serde_json::json!({"personalizations": []}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["errors"].is_array(), "SendGrid shape: {body}");

    let (status, _headers, bytes) = call(
        app,
        Method::POST,
        &format!("/v3/{}/messages", fixture.domain),
        &[],
        "application/x-www-form-urlencoded",
        b"from=a@b.c&to=d@e.f&subject=s".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["message"].is_string() && body.get("errors").is_none(),
        "Mailgun shape: {body}"
    );

    let (status, body) = post_json(
        app,
        Provider::Postmark,
        "",
        "/email",
        &serde_json::json!({"From": "a@b.c"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["ErrorCode"], 10, "Postmark shape: {body}");
    assert!(body["Message"].is_string());

    let (status, body) = post_json(
        app,
        Provider::Resend,
        "",
        "/emails",
        &serde_json::json!({"from": "a@b.c"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["statusCode"], 401, "Resend shape: {body}");
    assert_eq!(body["name"], "missing_api_key");
    assert!(body["message"].is_string());
}

/// An UNKNOWN key (well-formed, but not in the credential store) is refused
/// in every provider's shape — and never creates a message row.
#[tokio::test]
async fn unknown_keys_are_refused_in_each_providers_error_shape() {
    let Some(fixture) = fixture("compat_auth_unknown").await else {
        return;
    };
    let app = &fixture.app;
    let bogus = "am_test_00000000000000000000000000000000";

    let (status, body) = post_json(
        app,
        Provider::SendGrid,
        bogus,
        "/v3/mail/send",
        &serde_json::json!({"personalizations": []}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["errors"][0]["message"].is_string(), "{body}");

    let (name, value) = auth_header(Provider::Mailgun, bogus);
    let (status, _headers, bytes) = call(
        app,
        Method::POST,
        &format!("/v3/{}/messages", fixture.domain),
        &[(name, value)],
        "application/x-www-form-urlencoded",
        b"from=a@b.c&to=d@e.f&subject=s".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body["message"].is_string(), "{body}");

    let (status, body) = post_json(
        app,
        Provider::Postmark,
        bogus,
        "/email",
        &serde_json::json!({"From": "a@b.c"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["ErrorCode"], 10, "{body}");

    let (status, body) = post_json(
        app,
        Provider::Resend,
        bogus,
        "/emails",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["name"], "invalid_api_key", "{body}");

    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 0);
}

/// A valid key WITHOUT the `messages:send` scope is refused (403) in the
/// provider's shape — the same scope gate `POST /v1/messages` applies.
#[tokio::test]
async fn a_key_without_the_send_scope_is_refused_in_the_provider_shape() {
    let Some(fixture) = fixture("compat_auth_scope").await else {
        return;
    };
    let read_only = crate::app::test_support::seed_api_key_for(
        &fixture.pool,
        &fixture.tenant,
        &["messages:read"],
    )
    .await;

    let (status, body) = post_json(
        &fixture.app,
        Provider::SendGrid,
        &read_only,
        "/v3/mail/send",
        &serde_json::json!({
            "personalizations": [{"to": [{"email": "to@example.com"}]}],
            "from": {"email": format!("sender@{}", fixture.domain)},
            "subject": "s",
            "content": [{"type": "text/plain", "value": "t"}]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["errors"][0]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("messages:send"),
        "{body}"
    );

    let (status, body) = post_json(
        &fixture.app,
        Provider::Resend,
        &read_only,
        "/emails",
        &serde_json::json!({"from": format!("sender@{}", fixture.domain), "to": "to@example.com", "subject": "s", "text": "t"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["name"], "restricted_api_key", "{body}");

    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 0);
}

// ─── SendGrid ──────────────────────────────────────────────────

#[tokio::test]
async fn sendgrid_send_maps_every_field_onto_the_canonical_send_path() {
    let Some(fixture) = fixture("compat_sendgrid_send").await else {
        return;
    };
    let attachment_content = base64::engine::general_purpose::STANDARD.encode(b"hello attachment");
    let payload = serde_json::json!({
        "personalizations": [{
            "to": [
                {"email": "to@example.com", "name": "To One"},
                {"email": "to2@example.com"}
            ],
            "cc": [{"email": "cc@example.com"}],
            "bcc": [{"email": "bcc@example.com"}],
            "headers": {"X-Personalization": "yes"}
        }],
        "from": {"email": format!("sender@{}", fixture.domain), "name": "Sender Name"},
        "reply_to": {"email": "reply@example.com", "name": "Replies"},
        "subject": "SendGrid subject",
        "content": [
            {"type": "text/plain", "value": "plain body"},
            {"type": "text/html", "value": "<p>html body</p>"}
        ],
        "attachments": [{
            "content": attachment_content,
            "filename": "report.txt",
            "type": "text/plain"
        }],
        "categories": ["welcome"],
        "custom_args": {"campaign": "launch"}
    });
    let (name, value) = auth_header(Provider::SendGrid, &fixture.key);
    let smtpapi = serde_json::json!({
        "category": ["onboarding"],
        "unique_args": {"tenant_key": "abc"}
    })
    .to_string();

    let (status, headers, bytes) = call(
        &fixture.app,
        Method::POST,
        "/v3/mail/send",
        &[(name, value), ("x-smtpapi".to_string(), smtpapi)],
        "application/json",
        payload.to_string().into_bytes(),
    )
    .await;
    let body = String::from_utf8_lossy(&bytes).to_string();
    assert_eq!(status, StatusCode::ACCEPTED, "body: {body}");
    assert!(
        body.is_empty(),
        "SendGrid answers an empty 202 body: {body}"
    );
    let message_id = headers
        .get("x-message-id")
        .and_then(|value| value.to_str().ok())
        .expect("X-Message-Id header")
        .to_string();

    // The canonical path is what ran: the message row carries the mapping.
    let row = message_row(&fixture.pool, &fixture.tenant, &message_id).await;
    assert_eq!(row.from_email, format!("sender@{}", fixture.domain));
    assert_eq!(
        row.to_emails,
        serde_json::json!(["to@example.com", "to2@example.com"])
    );
    assert_eq!(row.cc_emails, Some(serde_json::json!(["cc@example.com"])));
    assert_eq!(row.bcc_emails, Some(serde_json::json!(["bcc@example.com"])));
    assert_eq!(row.subject, "SendGrid subject");
    assert_eq!(row.html_body.as_deref(), Some("<p>html body</p>"));
    assert_eq!(row.text_body.as_deref(), Some("plain body"));
    assert_eq!(
        row.tags,
        Some(serde_json::json!(["welcome", "onboarding"])),
        "categories[] + X-SMTPAPI category map onto tags"
    );
    assert_eq!(
        row.metadata,
        Some(serde_json::json!({"campaign": "launch", "tenant_key": "abc"}))
    );
    assert_eq!(row.reply_to.as_deref(), Some("Replies <reply@example.com>"));
    assert_eq!(
        row.attachments.as_ref().unwrap()[0]["filename"],
        "report.txt"
    );
    assert_eq!(
        row.attachments.as_ref().unwrap()[0]["contentType"],
        "text/plain"
    );
    assert_eq!(
        row.attachments.as_ref().unwrap()[0]["content"],
        base64::engine::general_purpose::STANDARD.encode(b"hello attachment")
    );
    let headers = row.headers.expect("stored MIME headers");
    assert_eq!(headers["custom"]["X-Personalization"], "yes");
    assert_eq!(headers["from_mailbox"]["name"], "Sender Name");
    assert_eq!(row.message_category, "marketing", "the canonical default");

    // …and the per-recipient fan-out ran through the same insert.
    let queued = queue_rows(&fixture.pool, &message_id).await;
    assert_eq!(queued.len(), 4, "to+to+cc+bcc queue rows");
    assert!(queued.iter().all(|row| row.1 == "SendGrid subject"));
    assert!(queued
        .iter()
        .all(|row| row.4 == Some(vec!["welcome".to_string(), "onboarding".to_string()])));
    assert!(queued.iter().all(|row| row.8 == "marketing"));
}

/// The `X-ApexMail-Category` extension is the documented opt-in for the
/// canonical server-owned category — and an invalid value is refused by the
/// canonical normalizer (validation parity, in the provider's shape).
#[tokio::test]
async fn sendgrid_category_extension_is_validated_by_the_canonical_normalizer() {
    let Some(fixture) = fixture("compat_sendgrid_category").await else {
        return;
    };
    let (name, value) = auth_header(Provider::SendGrid, &fixture.key);
    let payload = serde_json::json!({
        "personalizations": [{"to": [{"email": "to@example.com"}]}],
        "from": {"email": format!("sender@{}", fixture.domain)},
        "subject": "transactional",
        "content": [{"type": "text/plain", "value": "t"}]
    });

    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        "/v3/mail/send",
        &[
            (name.clone(), value.clone()),
            (CATEGORY_HEADER.to_string(), "transactional".to_string()),
        ],
        "application/json",
        payload.to_string().into_bytes(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let category: String = sqlx::query_scalar(
        "SELECT message_category FROM messages WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&fixture.tenant)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(category, "transactional");

    let (status, body) = {
        let (status, _headers, bytes) = call(
            &fixture.app,
            Method::POST,
            "/v3/mail/send",
            &[
                (name, value),
                (CATEGORY_HEADER.to_string(), "not a category!".to_string()),
            ],
            "application/json",
            payload.to_string().into_bytes(),
        )
        .await;
        (
            status,
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        )
    };
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["errors"][0]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("category"),
        "{body}"
    );
}

/// SendGrid payloads that cannot be mapped faithfully are refused by NAME —
/// never silently truncated or dropped.
#[tokio::test]
async fn sendgrid_unmappable_payloads_are_named_refusals() {
    let Some(fixture) = fixture("compat_sendgrid_refusals").await else {
        return;
    };
    let from = format!("sender@{}", fixture.domain);
    let base = |extra: serde_json::Value| {
        let mut payload = serde_json::json!({
            "personalizations": [{"to": [{"email": "to@example.com"}]}],
            "from": {"email": from},
            "subject": "s",
            "content": [{"type": "text/plain", "value": "t"}]
        });
        let object = payload.as_object_mut().unwrap();
        for (key, value) in extra.as_object().unwrap() {
            object.insert(key.clone(), value.clone());
        }
        payload
    };

    let cases: Vec<(serde_json::Value, &str)> = vec![
        (
            serde_json::json!({"personalizations": [
                {"to": [{"email": "to@example.com"}]},
                {"to": [{"email": "to2@example.com"}]}
            ]}),
            "more than one 'personalizations'",
        ),
        (
            serde_json::json!({"content": [
                {"type": "text/plain", "value": "a"},
                {"type": "text/plain", "value": "b"}
            ]}),
            "repeats a 'text/plain'",
        ),
        (
            serde_json::json!({"attachments": [{
                "content": "aGk=", "filename": "a.txt", "content_id": "cid-1"
            }]}),
            "content_id",
        ),
        (serde_json::json!({"template_id": "d-123"}), "template_id"),
        (
            serde_json::json!({"tracking_settings": {"click_tracking": {"enable": true}}}),
            "tracking_settings",
        ),
        (
            serde_json::json!({"mail_settings": {"bypass_list_management": {"enable": true}}}),
            "mail_settings",
        ),
    ];

    for (extra, expected) in cases {
        let (status, body) = post_json(
            &fixture.app,
            Provider::SendGrid,
            &fixture.key,
            "/v3/mail/send",
            &base(extra.clone()),
        )
        .await;
        let rendered = body.to_string();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{extra} -> {rendered}");
        assert!(
            rendered.contains(expected),
            "{extra} must be refused naming '{expected}': {rendered}"
        );
    }

    // An explicit no-op is accepted (sandbox disabled).
    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        "/v3/mail/send",
        &[auth_header(Provider::SendGrid, &fixture.key)],
        "application/json",
        base(serde_json::json!({"mail_settings": {"sandbox_mode": {"enable": false}}}))
            .to_string()
            .into_bytes(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(&bytes)
    );

    // A malformed X-SMTPAPI header is a named 400, not a silent ignore.
    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        "/v3/mail/send",
        &[
            auth_header(Provider::SendGrid, &fixture.key),
            ("x-smtpapi".to_string(), "{not json".to_string()),
        ],
        "application/json",
        base(serde_json::json!({})).to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&bytes).contains("X-SMTPAPI"));

    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 1);
}

/// Validation parity: a SUPPRESSED recipient, an UNVERIFIED sender domain and
/// a MISSING subject are refused by the canonical gates, in the provider's
/// shape, with nothing queued.
#[tokio::test]
async fn sendgrid_canonical_validation_refusals_keep_the_provider_shape() {
    let Some(fixture) = fixture("compat_sendgrid_validation").await else {
        return;
    };
    let from = format!("sender@{}", fixture.domain);
    let payload = |to: &str, subject: &str| {
        serde_json::json!({
            "personalizations": [{"to": [{"email": to}]}],
            "from": {"email": from},
            "subject": subject,
            "content": [{"type": "text/plain", "value": "t"}]
        })
    };

    // A suppressed recipient: the canonical suppression gate refuses, and the
    // refusal names the address (never a silent success).
    sqlx::query(
        "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at)
         VALUES ($1, $2, 'blocked@example.com', 'unsubscribe', 'test', NOW())",
    )
    .bind(apexmail_lib::id::generate_id("sup", 22))
    .bind(&fixture.tenant)
    .execute(&fixture.pool)
    .await
    .expect("seed suppression");

    let (status, body) = post_json(
        &fixture.app,
        Provider::SendGrid,
        &fixture.key,
        "/v3/mail/send",
        &payload("blocked@example.com", "suppressed"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.to_string().contains("blocked@example.com"),
        "the refusal must name the suppressed recipient: {body}"
    );

    // An unverified sender domain.
    let unverified = format!(
        "unverified-{}.example.com",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let (status, body) = post_json(
        &fixture.app,
        Provider::SendGrid,
        &fixture.key,
        "/v3/mail/send",
        &serde_json::json!({
            "personalizations": [{"to": [{"email": "to@example.com"}]}],
            "from": {"email": format!("sender@{unverified}")},
            "subject": "unverified",
            "content": [{"type": "text/plain", "value": "t"}]
        }),
    )
    .await;
    assert!(status.is_client_error(), "{status} {body}");
    assert!(body["errors"].is_array(), "{body}");

    // A missing subject: the canonical path requires one for a non-template
    // send, and the refusal arrives in SendGrid's shape.
    let (status, body) = post_json(
        &fixture.app,
        Provider::SendGrid,
        &fixture.key,
        "/v3/mail/send",
        &serde_json::json!({
            "personalizations": [{"to": [{"email": "to@example.com"}]}],
            "from": {"email": format!("sender@{}", fixture.domain)},
            "content": [{"type": "text/plain", "value": "t"}]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("subject"), "{body}");

    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 0);
}

// ─── Mailgun ───────────────────────────────────────────────────

#[tokio::test]
async fn mailgun_form_send_maps_every_field_onto_the_canonical_send_path() {
    let Some(fixture) = fixture("compat_mailgun_form").await else {
        return;
    };
    let (name, value) = auth_header(Provider::Mailgun, &fixture.key);
    let form = format!(
        "from=Mailer <sender@{}>&to=to@example.com&to=to2@example.com&cc=cc@example.com\
         &bcc=bcc@example.com&subject=Mailgun subject&text=plain&html=<p>html</p>\
         &o:tag=newsletter&v:customer_id=42&h:X-Campaign=spring&o:deliverytime={}",
        fixture.domain, "Fri, 15 Oct 2027 12:00:00 -0000"
    );

    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        &format!("/v3/{}/messages", fixture.domain),
        &[(name, value)],
        "application/x-www-form-urlencoded",
        form.into_bytes(),
    )
    .await;
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["message"], "Queued. Thank you.");
    let id = body["id"].as_str().expect("Mailgun id");
    assert!(
        id.starts_with('<') && id.ends_with(&format!("@{}>", fixture.domain)),
        "Mailgun id keeps its <id@domain> form: {id}"
    );
    let message_id = id
        .trim_start_matches('<')
        .split('@')
        .next()
        .unwrap()
        .to_string();

    let row = message_row(&fixture.pool, &fixture.tenant, &message_id).await;
    assert_eq!(row.from_email, format!("sender@{}", fixture.domain));
    assert_eq!(
        row.to_emails,
        serde_json::json!(["to@example.com", "to2@example.com"])
    );
    assert_eq!(row.cc_emails, Some(serde_json::json!(["cc@example.com"])));
    assert_eq!(row.bcc_emails, Some(serde_json::json!(["bcc@example.com"])));
    assert_eq!(row.subject, "Mailgun subject");
    assert_eq!(row.html_body.as_deref(), Some("<p>html</p>"));
    assert_eq!(row.text_body.as_deref(), Some("plain"));
    assert_eq!(row.tags, Some(serde_json::json!(["newsletter"])));
    assert_eq!(row.metadata, Some(serde_json::json!({"customer_id": "42"})));
    let headers = row.headers.expect("stored MIME headers");
    assert_eq!(headers["custom"]["X-Campaign"], "spring");
    assert_eq!(headers["from_mailbox"]["name"], "Mailer");

    let scheduled: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT scheduled_at FROM messages WHERE tenant_id = $1 AND id = $2::uuid",
    )
    .bind(&fixture.tenant)
    .bind(&message_id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert!(
        scheduled.is_some(),
        "o:deliverytime maps onto the canonical scheduled_at"
    );

    let queued = queue_rows(&fixture.pool, &message_id).await;
    assert_eq!(queued.len(), 4);
    assert!(queued.iter().all(|row| row.1 == "Mailgun subject"));
}

#[tokio::test]
async fn mailgun_multipart_send_carries_the_attachment_and_html() {
    let Some(fixture) = fixture("compat_mailgun_multipart").await else {
        return;
    };
    let (name, value) = auth_header(Provider::Mailgun, &fixture.key);
    let boundary = "----apexmail-compat-boundary";
    let mut body = Vec::new();
    let mut push_field = |name: &str, value: &str| {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    };
    push_field("from", &format!("sender@{}", fixture.domain));
    push_field("to", "to@example.com");
    push_field("subject", "with attachment");
    push_field("html", "<p>attached</p>");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"attachment\"; filename=\"invoice.pdf\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/pdf\r\n\r\n");
    body.extend_from_slice(b"%PDF-1.4 fake\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        &format!("/v3/{}/messages", fixture.domain),
        &[(name, value)],
        &format!("multipart/form-data; boundary={boundary}"),
        body,
    )
    .await;
    let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::OK, "{response}");
    let message_id = response["id"]
        .as_str()
        .unwrap()
        .trim_start_matches('<')
        .split('@')
        .next()
        .unwrap()
        .to_string();

    let row = message_row(&fixture.pool, &fixture.tenant, &message_id).await;
    assert_eq!(row.html_body.as_deref(), Some("<p>attached</p>"));
    let attachments = row.attachments.expect("attachment decoded");
    assert_eq!(attachments[0]["filename"], "invoice.pdf");
    assert_eq!(attachments[0]["contentType"], "application/pdf");
    assert_eq!(
        attachments[0]["content"],
        base64::engine::general_purpose::STANDARD.encode(b"%PDF-1.4 fake")
    );
}

/// The `{domain}` path segment is Mailgun's sending domain and must match the
/// sender's domain (the canonical path signs with the sender domain); every
/// unmappable Mailgun field is a named refusal.
#[tokio::test]
async fn mailgun_domain_mismatch_and_unmappable_fields_are_named_refusals() {
    let Some(fixture) = fixture("compat_mailgun_refusals").await else {
        return;
    };
    let (name, value) = auth_header(Provider::Mailgun, &fixture.key);
    let post = |body: String| {
        let app = fixture.app.clone();
        let name = name.clone();
        let value = value.clone();
        let uri = format!("/v3/{}/messages", fixture.domain);
        async move {
            let (status, _headers, bytes) = call(
                &app,
                Method::POST,
                &uri,
                &[(name, value)],
                "application/x-www-form-urlencoded",
                body.into_bytes(),
            )
            .await;
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes)
                    .unwrap_or(serde_json::Value::Null),
            )
        }
    };

    let (status, body) =
        post("from=sender@other.example.com&to=to@example.com&subject=s&text=t".to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("path segment"),
        "{body}"
    );

    let (status, body) = post(format!(
        "from=sender@{}&to=to@example.com&subject=s&text=t&o:testmode=yes&v:x=1",
        fixture.domain
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("o:testmode"),
        "{body}"
    );

    let (status, body) = post(format!(
        "from=sender@{}&to=to@example.com&subject=s&text=t&o:tracking-opens=no",
        fixture.domain
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("o:tracking-opens"),
        "{body}"
    );

    let (status, body) = post(format!(
        "from=sender@{}&to=to@example.com&subject=s&text=t&template=stored-template",
        fixture.domain
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("template"),
        "{body}"
    );

    let (status, body) = post(format!(
        "from=sender@{}&to=to@example.com&subject=s&text=t&definitely_unknown=1",
        fixture.domain
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("definitely_unknown"),
        "{body}"
    );

    // A malformed multipart body is a named refusal too, never an empty form.
    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        &format!("/v3/{}/messages", fixture.domain),
        &[(name, value)],
        "multipart/form-data; boundary=nope",
        b"not a multipart body".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&bytes).contains("boundary"));

    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 0);
}

/// `messages.mime` is wired and answers a NAMED 501 (after authentication),
/// and a bad credential there is refused as Mailgun would refuse it.
#[tokio::test]
async fn mailgun_messages_mime_answers_a_named_501() {
    let Some(fixture) = fixture("compat_mailgun_mime").await else {
        return;
    };
    let (name, value) = auth_header(Provider::Mailgun, &fixture.key);
    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        &format!("/v3/{}/messages.mime", fixture.domain),
        &[(name, value)],
        "multipart/form-data; boundary=x",
        b"--x--".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let message = body["message"].as_str().expect("Mailgun message shape");
    assert!(message.contains("messages.mime"), "{message}");
    assert!(
        message.contains(super::mailgun::mime_not_implemented()),
        "{message}"
    );

    // The credential gate runs FIRST: a bad key is a 401, not a 501.
    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        &format!("/v3/{}/messages.mime", fixture.domain),
        &[(
            "authorization".to_string(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("api:am_test_nope")
            ),
        )],
        "multipart/form-data; boundary=x",
        b"--x--".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(String::from_utf8_lossy(&bytes).contains("message"));
}

// ─── Postmark ──────────────────────────────────────────────────

#[tokio::test]
async fn postmark_send_maps_every_field_onto_the_canonical_send_path() {
    let Some(fixture) = fixture("compat_postmark_send").await else {
        return;
    };
    let payload = serde_json::json!({
        "From": format!("Sender <sender@{}>", fixture.domain),
        "To": "To One <to@example.com>, to2@example.com",
        "Cc": "cc@example.com",
        "Bcc": "bcc@example.com",
        "Subject": "Postmark subject",
        "HtmlBody": "<p>pm html</p>",
        "TextBody": "pm text",
        "ReplyTo": "reply@example.com",
        "Tag": "transactional-tag",
        "Metadata": {"order_id": "1234"},
        "MessageStream": "outbound",
        "TrackOpens": true,
        "Headers": [
            {"Name": "X-Campaign", "Value": "spring"},
            {"Name": "Reply-To", "Value": "reply@example.com"}
        ],
        "Attachments": [{
            "Name": "note.txt",
            "Content": base64::engine::general_purpose::STANDARD.encode(b"pm bytes"),
            "ContentType": "text/plain"
        }]
    });

    let (status, body) = post_json(
        &fixture.app,
        Provider::Postmark,
        &fixture.key,
        "/email",
        &payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ErrorCode"], 0);
    assert_eq!(body["Message"], "OK");
    let message_id = body["MessageID"].as_str().expect("MessageID").to_string();
    uuid::Uuid::parse_str(&message_id).expect("Postmark MessageID is the canonical uuid");

    let row = message_row(&fixture.pool, &fixture.tenant, &message_id).await;
    assert_eq!(row.from_email, format!("sender@{}", fixture.domain));
    assert_eq!(
        row.to_emails,
        serde_json::json!(["to@example.com", "to2@example.com"])
    );
    assert_eq!(row.cc_emails, Some(serde_json::json!(["cc@example.com"])));
    assert_eq!(row.bcc_emails, Some(serde_json::json!(["bcc@example.com"])));
    assert_eq!(row.subject, "Postmark subject");
    assert_eq!(row.html_body.as_deref(), Some("<p>pm html</p>"));
    assert_eq!(row.text_body.as_deref(), Some("pm text"));
    assert_eq!(row.tags, Some(serde_json::json!(["transactional-tag"])));
    assert_eq!(row.metadata, Some(serde_json::json!({"order_id": "1234"})));
    assert_eq!(
        row.message_category, "transactional",
        "MessageStream=outbound maps onto the transactional category"
    );
    // `Headers[].Reply-To` folds into the dedicated canonical field (the
    // same value as `ReplyTo` here — set differently it would be a named
    // refusal, covered by the refusals suite).
    assert_eq!(row.reply_to.as_deref(), Some("reply@example.com"));
    let headers = row.headers.expect("stored MIME headers");
    assert_eq!(headers["custom"]["X-Campaign"], "spring");
    assert_eq!(
        headers["custom"].get("Reply-To"),
        None,
        "never a raw protected header"
    );
    assert_eq!(row.attachments.as_ref().unwrap()[0]["filename"], "note.txt");

    let queued = queue_rows(&fixture.pool, &message_id).await;
    assert_eq!(queued.len(), 4);
    assert!(queued.iter().all(|row| row.8 == "transactional"));
}

/// `/email/batch` maps the canonical per-item results into Postmark's
/// ordered array — including a partial batch, which is never reported as a
/// full success.
#[tokio::test]
async fn postmark_batch_maps_per_item_results_in_request_order() {
    let Some(fixture) = fixture("compat_postmark_batch").await else {
        return;
    };
    let from = format!("sender@{}", fixture.domain);
    let payload = serde_json::json!([
        {
            "From": from,
            "To": "good@example.com",
            "Subject": "first",
            "TextBody": "one"
        },
        {
            "From": from,
            "To": "bad@example.com",
            "Subject": "",
            "TextBody": "two"
        }
    ]);

    let (status, body) = post_json(
        &fixture.app,
        Provider::Postmark,
        &fixture.key,
        "/email/batch",
        &payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = body.as_array().expect("Postmark batch answers an array");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["ErrorCode"], 0, "{body}");
    let message_id = results[0]["MessageID"].as_str().expect("first MessageID");
    assert_eq!(results[1]["ErrorCode"], 406, "{body}");
    assert!(
        results[1]["Message"].as_str().unwrap().contains("subject"),
        "{body}"
    );
    assert!(results[1]["MessageID"].is_null());

    // Only the accepted item is queued, through the canonical batch path.
    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 1);
    let queued = queue_rows(&fixture.pool, message_id).await;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].1, "first");
}

#[tokio::test]
async fn postmark_batch_ceiling_and_unmappable_fields_are_named_refusals() {
    let Some(fixture) = fixture("compat_postmark_refusals").await else {
        return;
    };
    let from = format!("sender@{}", fixture.domain);
    let oversized: Vec<serde_json::Value> = (0..501)
        .map(|_| serde_json::json!({"From": from, "To": "to@example.com", "Subject": "s"}))
        .collect();
    let (status, body) = post_json(
        &fixture.app,
        Provider::Postmark,
        &fixture.key,
        "/email/batch",
        &serde_json::Value::Array(oversized),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["ErrorCode"], 422);
    assert!(body["Message"].as_str().unwrap().contains("500"), "{body}");

    // Inside Postmark's own ceiling but above the CANONICAL batch ceiling
    // (API_MESSAGES_MAX_BATCH_SIZE, 100 by default) the canonical refusal is
    // mapped into Postmark's shape rather than silently chunked.
    let over_canonical: Vec<serde_json::Value> = (0..150)
        .map(|_| serde_json::json!({"From": from, "To": "to@example.com", "Subject": "s"}))
        .collect();
    let (status, body) = post_json(
        &fixture.app,
        Provider::Postmark,
        &fixture.key,
        "/email/batch",
        &serde_json::Value::Array(over_canonical),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["Message"].as_str().unwrap().contains("batch size"),
        "the canonical batch ceiling refusal keeps its reason: {body}"
    );

    for (payload, expected) in [
        (
            serde_json::json!({"TemplateId": "1234", "From": from, "To": "to@example.com", "Subject": "s"}),
            "TemplateId",
        ),
        (
            serde_json::json!({"TemplateAlias": "welcome", "From": from, "To": "to@example.com"}),
            "TemplateAlias",
        ),
        (
            serde_json::json!({
                "From": from, "To": "to@example.com", "Subject": "s",
                "InlineImages": [{"Name": "x", "Content": "aGk=", "ContentID": "cid"}]
            }),
            "InlineImages",
        ),
        (
            serde_json::json!({"From": from, "To": "to@example.com", "Subject": "s", "TrackLinks": false}),
            "TrackLinks",
        ),
        (
            serde_json::json!({"From": from, "To": "to@example.com", "Subject": "s", "MessageStream": "unknown"}),
            "MessageStream",
        ),
    ] {
        let (status, body) = post_json(
            &fixture.app,
            Provider::Postmark,
            &fixture.key,
            "/email",
            &payload,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{payload} -> {body}"
        );
        assert_eq!(body["ErrorCode"], 422, "{body}");
        assert!(
            body["Message"].as_str().unwrap().contains(expected),
            "{payload} must name '{expected}': {body}"
        );
    }

    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 0);
}

// ─── Resend ────────────────────────────────────────────────────

#[tokio::test]
async fn resend_send_maps_every_field_and_replays_idempotently() {
    let Some(fixture) = fixture("compat_resend_send").await else {
        return;
    };
    let payload = serde_json::json!({
        "from": format!("ApexMail <sender@{}>", fixture.domain),
        "to": ["to@example.com", "to2@example.com"],
        "cc": "cc@example.com",
        "bcc": ["bcc@example.com"],
        "subject": "Resend subject",
        "html": "<p>resend html</p>",
        "text": "resend text",
        "reply_to": "reply@example.com",
        "headers": {"X-Campaign": "spring"},
        "tags": [{"name": "category", "value": "welcome"}],
        "scheduled_at": "2027-10-15T12:00:00Z",
        "attachments": [{
            "filename": "note.txt",
            "content": base64::engine::general_purpose::STANDARD.encode(b"resend bytes")
        }]
    });

    let (name, value) = auth_header(Provider::Resend, &fixture.key);
    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        "/emails",
        &[
            (name.clone(), value.clone()),
            ("idempotency-key".to_string(), "compat-resend-1".to_string()),
        ],
        "application/json",
        payload.to_string().into_bytes(),
    )
    .await;
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    let message_id = body["id"].as_str().expect("Resend id").to_string();

    let row = message_row(&fixture.pool, &fixture.tenant, &message_id).await;
    assert_eq!(row.from_email, format!("sender@{}", fixture.domain));
    assert_eq!(
        row.to_emails,
        serde_json::json!(["to@example.com", "to2@example.com"])
    );
    assert_eq!(row.cc_emails, Some(serde_json::json!(["cc@example.com"])));
    assert_eq!(row.bcc_emails, Some(serde_json::json!(["bcc@example.com"])));
    assert_eq!(row.subject, "Resend subject");
    assert_eq!(row.html_body.as_deref(), Some("<p>resend html</p>"));
    assert_eq!(row.text_body.as_deref(), Some("resend text"));
    assert_eq!(row.tags, Some(serde_json::json!(["category:welcome"])));
    assert_eq!(row.reply_to.as_deref(), Some("reply@example.com"));
    let headers = row.headers.expect("stored MIME headers");
    assert_eq!(headers["custom"]["X-Campaign"], "spring");
    assert_eq!(row.attachments.as_ref().unwrap()[0]["filename"], "note.txt");
    assert_eq!(
        row.attachments.as_ref().unwrap()[0]["contentType"],
        "application/octet-stream",
        "a missing content_type defaults explicitly"
    );

    // Retry with the same Idempotency-Key: the canonical durable ledger
    // replays the SAME message, re-rendered into the Resend shape.
    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        "/emails",
        &[
            (name, value),
            ("idempotency-key".to_string(), "compat-resend-1".to_string()),
        ],
        "application/json",
        payload.to_string().into_bytes(),
    )
    .await;
    let replay: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["id"], serde_json::json!(message_id));
    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 1);
}

#[tokio::test]
async fn resend_batch_maps_data_in_request_order() {
    let Some(fixture) = fixture("compat_resend_batch").await else {
        return;
    };
    let from = format!("sender@{}", fixture.domain);
    let payload = serde_json::json!([
        {"from": from, "to": "good@example.com", "subject": "first", "text": "one"},
        {"from": from, "to": "bad@example.com", "subject": "", "text": "two"}
    ]);
    let (status, body) = post_json(
        &fixture.app,
        Provider::Resend,
        &fixture.key,
        "/emails/batch",
        &payload,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let data = body["data"]
        .as_array()
        .expect("Resend batch answers {data:[…]}");
    assert_eq!(data.len(), 2);
    assert!(data[0]["id"].is_string(), "{body}");
    assert_eq!(data[1]["error"]["statusCode"], 422, "{body}");
    assert!(data[1]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("subject"));
    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 1);
}

#[tokio::test]
async fn resend_unmappable_fields_are_named_refusals() {
    let Some(fixture) = fixture("compat_resend_refusals").await else {
        return;
    };
    let from = format!("sender@{}", fixture.domain);
    let cases: Vec<(serde_json::Value, &str)> = vec![
        (
            serde_json::json!({
                "from": from, "to": "to@example.com", "subject": "s",
                "attachments": [{"filename": "a.pdf", "path": "https://example.com/a.pdf"}]
            }),
            "path",
        ),
        (
            serde_json::json!({
                "from": from, "to": "to@example.com", "subject": "s",
                "scheduled_at": "in 1 min"
            }),
            "ISO 8601",
        ),
        (
            serde_json::json!({
                "from": from, "to": "to@example.com", "subject": "s",
                "template": {"id": "tmpl_1", "variables": {"a": "b"}}
            }),
            "template",
        ),
        (
            serde_json::json!({
                "from": from, "to": "to@example.com", "subject": "s",
                "audience_id": "aud_1"
            }),
            "audience_id",
        ),
    ];
    for (payload, expected) in cases {
        let (status, body) = post_json(
            &fixture.app,
            Provider::Resend,
            &fixture.key,
            "/emails",
            &payload,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{payload} -> {body}"
        );
        assert_eq!(body["name"], "validation_error", "{body}");
        assert!(
            body["message"].as_str().unwrap().contains(expected),
            "{payload} must name '{expected}': {body}"
        );
    }
    // The provider's own batch ceiling (Resend answers its validation error
    // shape — 422 — for an unusable batch).
    let oversized: Vec<serde_json::Value> = (0..101)
        .map(|_| serde_json::json!({"from": from, "to": "to@example.com", "subject": "s"}))
        .collect();
    let (status, body) = post_json(
        &fixture.app,
        Provider::Resend,
        &fixture.key,
        "/emails/batch",
        &serde_json::Value::Array(oversized),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["name"], "validation_error", "{body}");
    assert!(body["message"].as_str().unwrap().contains("100"), "{body}");
    assert_eq!(message_count(&fixture.pool, &fixture.tenant).await, 0);
}

// ─── Surface-level contracts ───────────────────────────────────

/// Every compat route is registered on the REAL app: a POST with a VALID
/// credential reaches the mapping layer (its own named refusal — never a 404),
/// while an unknown sibling path still 404s (so the assertion is not vacuous).
#[tokio::test]
async fn every_compat_route_is_wired_on_the_real_app() {
    let Some(fixture) = fixture("compat_routes_wired").await else {
        return;
    };
    let _state: &AppState = &fixture.state;

    let mailgun_auth = auth_header(Provider::Mailgun, &fixture.key);
    let cases: Vec<(Provider, &str, &str, &str, &str)> = vec![
        (
            Provider::SendGrid,
            "/v3/mail/send",
            "application/json",
            "{}",
            "personalizations",
        ),
        (
            Provider::Mailgun,
            "/v3/example.com/messages",
            "application/x-www-form-urlencoded",
            "",
            "from",
        ),
        (
            Provider::Postmark,
            "/email",
            "application/json",
            "{}",
            "From",
        ),
        (
            Provider::Postmark,
            "/email/batch",
            "application/json",
            "{}",
            "array",
        ),
        (
            Provider::Resend,
            "/emails",
            "application/json",
            "{}",
            "from",
        ),
        (
            Provider::Resend,
            "/emails/batch",
            "application/json",
            "{}",
            "array",
        ),
    ];

    for (provider, uri, media_type, body, expected) in cases {
        let (name, value) = auth_header(provider, &fixture.key);
        let (status, _headers, bytes) = call(
            &fixture.app,
            Method::POST,
            uri,
            &[(name, value)],
            media_type,
            body.as_bytes().to_vec(),
        )
        .await;
        let rendered = String::from_utf8_lossy(&bytes).to_string();
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{uri} must be registered on the app (a missing route 404s): {rendered}"
        );
        assert!(
            status.is_client_error(),
            "{uri} with an empty payload must be a named provider refusal: {status} {rendered}"
        );
        assert!(
            rendered.contains(expected),
            "{uri} must name the missing field '{expected}': {rendered}"
        );
    }

    // The Mailgun `.mime` placeholder is a named 501 (not a client error).
    let (status, _headers, bytes) = call(
        &fixture.app,
        Method::POST,
        "/v3/example.com/messages.mime",
        &[mailgun_auth],
        "multipart/form-data; boundary=x",
        b"--x--".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert!(String::from_utf8_lossy(&bytes).contains("messages.mime"));

    // …and an unknown sibling path still 404s.
    let (status, _headers, _bytes) = call(
        &fixture.app,
        Method::POST,
        "/v3/mail/send/extra",
        &[auth_header(Provider::SendGrid, &fixture.key)],
        "application/json",
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
