//! Per-provider x kind tests for the importer: real-format fixtures, the
//! over-10k streaming proof, conflict/dedupe behaviour, template conversion
//! (and its `needs_review` marker), malformed-file refusals, scope refusal
//! and the dry-run-writes-nothing contract.
//!
//! Fixtures are tiny inline files in the providers' own shapes (self-contained
//! — no fixture directory to drift).

#![cfg(test)]

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use crate::app::test_support::adv::AdvEnv;

// ─── Fixtures (inline, real-format) ────────────────────────────

/// SendGrid bounces CSV export (`email,created,reason,status`).
const SENDGRID_BOUNCES_CSV: &str = "\
email,created,reason,status
alice@example.com,2026-08-01 10:00:00,550 5.1.1 The email account that you tried to reach does not exist,5.1.1
bob@example.com,2026-08-02 11:30:00,452 4.2.2 The email account is over quota,4.2.2
carol@example.com,2026-08-03 09:15:00,550 Unknown user,5.1.1
not-an-email,2026-08-04 09:15:00,550 Unknown user,5.1.1
";

/// SendGrid blocks CSV export (same columns; the reason text is a block).
const SENDGRID_BLOCKS_CSV: &str = "\
email,created,reason,status
blocked@example.com,2026-08-05 08:00:00,550 Rejected due to a prior bounce,5.1.1
";

/// SendGrid spam-report CSV export (email, created, ip — no reason column).
const SENDGRID_SPAM_CSV: &str = "\
email,created,ip
spammy@example.com,2026-08-06 12:00:00,203.0.113.7
";

/// Mailgun bounces JSON (`GET /v3/{domain}/bounces` page shape).
const MAILGUN_BOUNCES_JSON: &str = r#"{
  "items": [
    {"address": "dave@example.com", "code": "550", "error": "5.1.1 The email account that you tried to reach does not exist", "created_at": "2026-08-07T10:00:00Z"},
    {"address": "erin@example.com", "code": "450", "error": "4.7.0 Try again later", "created_at": "2026-08-07T10:05:00Z"}
  ],
  "paging": {"first": "https://api.mailgun.net/v3/x/bounces?page=first", "next": "https://api.mailgun.net/v3/x/bounces?page=next"}
}"#;

/// Mailgun unsubscribes JSON.
const MAILGUN_UNSUBSCRIBES_JSON: &str = r#"{
  "items": [
    {"address": "frank@example.com", "tags": ["campaign"], "created_at": "2026-08-08T09:00:00Z"}
  ],
  "paging": {}
}"#;

/// Postmark bounces JSON (`GET /bounces` shape).
const POSTMARK_BOUNCES_JSON: &str = r#"{
  "TotalCount": 3,
  "Bounces": [
    {"ID": 1, "Type": "HardBounce", "TypeCode": 1, "Name": "Hard bounce", "Email": "grace@example.com", "Description": "The server was unable to deliver your message", "BouncedAt": "2026-08-09T10:00:00Z"},
    {"ID": 2, "Type": "Transient", "TypeCode": 2, "Name": "Message delay", "Email": "heidi@example.com", "Description": "The server was temporarily unable to deliver", "BouncedAt": "2026-08-09T11:00:00Z"},
    {"ID": 3, "Type": "SpamComplaint", "TypeCode": 100, "Name": "Spam complaint", "Email": "ivan@example.com", "Description": "The recipient marked the message as spam", "BouncedAt": "2026-08-09T12:00:00Z"}
  ]
}"#;

/// Resend suppressions JSON (`{"data": […]}` envelope).
const RESEND_SUPPRESSIONS_JSON: &str = r#"{
  "data": [
    {"id": "sup_1", "email": "judy@example.com", "reason": "hard bounce", "created_at": "2026-08-10T08:00:00Z"},
    {"id": "sup_2", "email": "ken@example.com", "reason": "spam complaint", "created_at": "2026-08-10T09:00:00Z"}
  ]
}"#;

/// Resend suppressions CSV (same column shape as SendGrid's).
const RESEND_SUPPRESSIONS_CSV: &str = "\
email,created,reason
laura@example.com,2026-08-11 08:00:00,hard bounce
";

/// SendGrid Marketing Campaigns contacts CSV.
const SENDGRID_CONTACTS_CSV: &str = "\
email,first_name,last_name,address_line_1,city,country,unsubscribed
mira@example.com,Mira,Van der Berg,1 Main St,Berlin,DE,false
noah@example.com,Noah,Smith,2 Side St,Paris,FR,true
";

/// Mailgun mailing-list members JSON.
const MAILGUN_CONTACTS_JSON: &str = r#"{
  "items": [
    {"address": "olive@example.com", "name": "Olive Black", "subscribed": true, "vars": {"plan": "pro"}},
    {"address": "pete@example.com", "name": "Pete Green", "subscribed": false}
  ],
  "paging": {}
}"#;

/// Postmark message-stream subscribers CSV.
const POSTMARK_CONTACTS_CSV: &str = "\
EmailAddress,FirstName,LastName,Status,SubmittedAt
quinn@example.com,Quinn,Adams,Subscribed,2026-08-01T00:00:00Z
rita@example.com,Rita,Brown,Unsubscribed,2026-08-01T00:00:00Z
";

/// Resend audience contacts JSON.
const RESEND_CONTACTS_JSON: &str = r#"{
  "data": [
    {"id": "c_1", "email": "sam@example.com", "first_name": "Sam", "last_name": "Cole", "unsubscribed": false},
    {"id": "c_2", "email": "tara@example.com", "first_name": "Tara", "last_name": "Dunn", "unsubscribed": true}
  ]
}"#;

/// SendGrid transactional-template export (handlebars).
const SENDGRID_TEMPLATES_JSON: &str = r#"{
  "templates": [
    {
      "id": "d-abc",
      "name": "welcome-email",
      "subject": "Welcome {{ first_name }}",
      "html_content": "<h1>Hello {{ first_name }}</h1><p>We are glad you are here.</p>"
    },
    {
      "id": "d-def",
      "name": "order-receipt",
      "subject": "Your receipt",
      "html_content": "<ul>{{#each items}}<li>{{this.name}}</li>{{/each}}</ul><p>{{{raw_note}}}</p>"
    }
  ]
}"#;

/// SendGrid legacy template (the `[%tag%]` dialect).
const SENDGRID_LEGACY_TEMPLATES_JSON: &str = r#"[
  {"name": "legacy-hello", "subject": "Hi [%first_name%]", "html_content": "<p>Hello [%first_name%]</p>"}
]"#;

/// Mailgun template JSON with the Go-style dotted path and a nested body.
const MAILGUN_TEMPLATES_JSON: &str = r#"{
  "items": [
    {"name": "mailgun-welcome", "subject": "Hello {{ .name }}", "html": "<p>Hi {{ .name }}</p>"}
  ]
}"#;

/// Postmark templates JSON.
const POSTMARK_TEMPLATES_JSON: &str = r#"{
  "Templates": [
    {"TemplateId": 1, "Name": "postmark-welcome", "Subject": "Welcome", "HtmlBody": "<p>Hello {{name}}</p>", "TextBody": "Hello {{name}}"}
  ]
}"#;

/// Resend templates JSON (triple-brace variable syntax).
const RESEND_TEMPLATES_JSON: &str = r#"{
  "data": [
    {"id": "tpl_1", "name": "resend-welcome", "subject": "Welcome {{{NAME}}}", "html": "<p>Hi {{{NAME}}}</p>"}
  ]
}"#;

// ─── Harness ───────────────────────────────────────────────────

/// A tenant (plan chosen per test: templates need `growth` for the
/// custom_templates entitlement) with an API key of `scopes`, driving the
/// REAL `build_app` router.
async fn fixture(pool: &PgPool, plan: &str, scopes: &[&str]) -> (AdvEnv, String) {
    let tenant_id = apexmail_lib::id::generate_id("impt", 20);
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
         VALUES ($1, 'import fixture', $2, $3, 'active', NOW(), NOW())",
    )
    .bind(&tenant_id)
    .bind(format!("slug-{tenant_id}"))
    .bind(plan)
    .execute(pool)
    .await
    .expect("seed import tenant");
    let key = crate::app::test_support::seed_api_key_for(pool, &tenant_id, scopes).await;
    let mut env = AdvEnv::over(pool.clone(), key).await;
    env.tenant_id = tenant_id.clone();
    (env, tenant_id)
}

/// POST raw provider-export bytes with an explicit Content-Type (the
/// provider's own: text/csv or application/json).
async fn post_file(
    env: &AdvEnv,
    uri: &str,
    content_type: &str,
    body: &[u8],
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, content_type)
        .header("x-api-key", &env.credential)
        .body(Body::from(body.to_vec()))
        .expect("request");
    let response = env.app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn stored_source(pool: &PgPool, tenant: &str, email: &str) -> Option<(String, String)> {
    sqlx::query_as("SELECT reason, source FROM suppressions WHERE tenant_id = $1 AND email = $2")
        .bind(tenant)
        .bind(email)
        .fetch_optional(pool)
        .await
        .expect("suppression row")
}

// ─── Suppressions: four providers, happy path ──────────────────

#[tokio::test]
async fn sendgrid_bounces_import_with_provenance_and_reason_mapping() {
    let Some(pool) = crate::test_db::canonical_pool("imp_sg_bounces").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["suppressions:write", "suppressions:read"]).await;

    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions?mode=commit&source_type=bounces",
        "text/csv",
        SENDGRID_BOUNCES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["rows"], 4);
    assert_eq!(body["counts"]["imported"], 3, "one invalid row: {body}");
    assert_eq!(body["counts"]["invalid"], 1);
    assert_eq!(body["suppressions"]["source_type"], "bounces");
    let by_reason: Vec<(String, u64)> = body["suppressions"]["by_reason"]
        .as_array()
        .expect("by_reason")
        .iter()
        .map(|row| {
            (
                row["reason"].as_str().unwrap().to_string(),
                row["count"].as_u64().unwrap(),
            )
        })
        .collect();
    assert!(
        by_reason.contains(&("hard_bounce".into(), 2)),
        "{by_reason:?}"
    );
    assert!(
        by_reason.contains(&("temporary".into(), 1)),
        "{by_reason:?}"
    );

    // Provenance: source is `<provider>_import`, and the provider's own
    // `created` timestamp is the row's created_at.
    let (reason, source) = stored_source(&pool, &tenant, "alice@example.com")
        .await
        .expect("alice row");
    assert_eq!(reason, "hard_bounce");
    assert_eq!(source, "sendgrid_import");
    let (reason, _) = stored_source(&pool, &tenant, "bob@example.com")
        .await
        .expect("bob row");
    assert_eq!(reason, "temporary", "4.2.2 is a soft bounce");
    let (created,): (chrono::DateTime<chrono::Utc>,) =
        sqlx::query_as("SELECT created_at FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind("alice@example.com")
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(
        created.to_rfc3339(),
        "2026-08-01T10:00:00+00:00",
        "the provider's own timestamp is preserved"
    );
    assert!(stored_source(&pool, &tenant, "not-an-email")
        .await
        .is_none());

    // The campaign gate reads the row: alice is suppressed.
    let (status, body) = env
        .get(&format!("/v1/suppressions/check/{}", "alice@example.com"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["suppressed"], true, "{body}");
}

#[tokio::test]
async fn sendgrid_blocks_and_spam_reports_map_to_canonical_reasons() {
    let Some(pool) = crate::test_db::canonical_pool("imp_sg_blocks").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["suppressions:write", "suppressions:read"]).await;

    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions?mode=commit&source_type=blocks",
        "text/csv",
        SENDGRID_BLOCKS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (reason, source) = stored_source(&pool, &tenant, "blocked@example.com")
        .await
        .expect("blocked row");
    assert_eq!(reason, "customer_block");
    assert_eq!(source, "sendgrid_import");

    // No source_type: the spam-report shape (ip column, no reason) is sniffed.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions?mode=commit",
        "text/csv",
        SENDGRID_SPAM_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["suppressions"]["source_type"], "spam_reports",
        "{body}"
    );
    let (reason, _) = stored_source(&pool, &tenant, "spammy@example.com")
        .await
        .expect("spam row");
    assert_eq!(
        reason, "complaint",
        "spam reports are complaints, which are compliance-protected"
    );

    // …and the canonical policy protects that row from removal.
    let (status, body) = env.get("/v1/suppressions?reason=complaint").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body[0]["id"].as_str().expect("id").to_string();
    let (status, body) = env.delete(&format!("/v1/suppressions/{id}")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an imported complaint must be irremovable through the canonical policy: {body}"
    );
}

#[tokio::test]
async fn mailgun_bounces_and_unsubscribes_import() {
    let Some(pool) = crate::test_db::canonical_pool("imp_mg").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["suppressions:write"]).await;

    let (status, body) = post_file(
        &env,
        "/v1/import/mailgun/suppressions?mode=commit&source_type=bounces",
        "application/json",
        MAILGUN_BOUNCES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["imported"], 2, "{body}");
    let (reason, source) = stored_source(&pool, &tenant, "dave@example.com")
        .await
        .expect("dave row");
    assert_eq!(reason, "hard_bounce", "550 is permanent");
    assert_eq!(source, "mailgun_import");
    let (reason, _) = stored_source(&pool, &tenant, "erin@example.com")
        .await
        .expect("erin row");
    assert_eq!(reason, "temporary", "450 is transient");

    let (status, body) = post_file(
        &env,
        "/v1/import/mailgun/suppressions?mode=commit&source_type=unsubscribes",
        "application/json",
        MAILGUN_UNSUBSCRIBES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (reason, source) = stored_source(&pool, &tenant, "frank@example.com")
        .await
        .expect("frank row");
    assert_eq!(
        reason, "marketing_unsubscribe",
        "an unsubscribe import must land as the protected unsubscribe reason"
    );
    assert_eq!(source, "mailgun_import");
}

#[tokio::test]
async fn postmark_bounces_import_type_mapping() {
    let Some(pool) = crate::test_db::canonical_pool("imp_pm").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["suppressions:write"]).await;

    let (status, body) = post_file(
        &env,
        "/v1/import/postmark/suppressions?mode=commit",
        "application/json",
        POSTMARK_BOUNCES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["imported"], 3, "{body}");
    assert_eq!(
        stored_source(&pool, &tenant, "grace@example.com")
            .await
            .unwrap()
            .0,
        "hard_bounce"
    );
    assert_eq!(
        stored_source(&pool, &tenant, "heidi@example.com")
            .await
            .unwrap()
            .0,
        "temporary"
    );
    assert_eq!(
        stored_source(&pool, &tenant, "ivan@example.com")
            .await
            .unwrap()
            .0,
        "complaint"
    );
    let (_, source) = stored_source(&pool, &tenant, "grace@example.com")
        .await
        .unwrap();
    assert_eq!(source, "postmark_import");
}

#[tokio::test]
async fn resend_suppressions_import_json_and_csv() {
    let Some(pool) = crate::test_db::canonical_pool("imp_rs").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["suppressions:write"]).await;

    let (status, body) = post_file(
        &env,
        "/v1/import/resend/suppressions?mode=commit",
        "application/json",
        RESEND_SUPPRESSIONS_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        stored_source(&pool, &tenant, "judy@example.com")
            .await
            .unwrap()
            .0,
        "hard_bounce"
    );
    assert_eq!(
        stored_source(&pool, &tenant, "ken@example.com")
            .await
            .unwrap()
            .0,
        "complaint"
    );

    let (status, body) = post_file(
        &env,
        "/v1/import/resend/suppressions?mode=commit",
        "text/csv",
        RESEND_SUPPRESSIONS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, source) = stored_source(&pool, &tenant, "laura@example.com")
        .await
        .unwrap();
    assert_eq!(source, "resend_import");
}

// ─── Suppressions: >10k streaming, conflicts, dry run, malformed ─

/// The cap evidence: the inline bulk endpoint refuses >10,000 entries; the
/// importer streams 100,000 rows through in chunked statements. The fixture is
/// generated (real SendGrid column shape), so the assertion is about the
/// streaming path, not about a checked-in file.
#[tokio::test]
async fn hundred_thousand_suppressions_stream_through_the_importer() {
    let Some(pool) = crate::test_db::canonical_pool("imp_stream_100k").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["suppressions:write"]).await;

    const ROWS: usize = 100_000;
    let unique = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let mut csv = String::with_capacity(ROWS * 40);
    csv.push_str("email,created,reason,status\n");
    for index in 0..ROWS {
        csv.push_str(&format!(
            "bulk-{unique}-{index}@example.com,2026-08-01 10:00:00,550 User unknown,5.1.1\n"
        ));
    }

    // The inline bulk endpoint's 10,000-entry refusal, first (the behaviour
    // the importer deliberately exceeds).
    let oversized: Vec<serde_json::Value> = (0..10_001)
        .map(|index| json!({ "email": format!("x{index}@example.com"), "reason": "bounce" }))
        .collect();
    let (status, _) = env
        .post(
            "/v1/suppressions/bulk",
            &json!({ "entries": oversized }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the inline cap still applies"
    );

    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions?mode=commit",
        "text/csv",
        csv.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["rows"], ROWS);
    assert_eq!(body["counts"]["imported"], ROWS);
    assert_eq!(body["counts"]["duplicates"], 0);

    let stored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND source = 'sendgrid_import'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(stored, ROWS as i64, "every streamed row landed");

    // Replaying the identical file writes nothing: all duplicates.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions?mode=commit",
        "text/csv",
        csv.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["imported"], 0, "replay is idempotent");
    assert_eq!(body["counts"]["duplicates"], ROWS);
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(stored, ROWS as i64);
}

#[tokio::test]
async fn suppression_conflicts_keep_the_existing_row_and_dry_run_writes_nothing() {
    let Some(pool) = crate::test_db::canonical_pool("imp_sg_conflict").await else {
        return;
    };
    // Read scope included: the stored report is fetched back below (the
    // repo's reads-need-read-scopes rule, same as every canonical GET).
    let (env, tenant) = fixture(&pool, "free", &["suppressions:write", "suppressions:read"]).await;

    // A manual row the operator typed; the import must NOT overwrite it.
    let (status, body) = env
        .post(
            "/v1/suppressions",
            &json!({"email": "carol@example.com", "reason": "complaint", "source": "manual"})
                .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Dry run first: identical counts, zero writes.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions",
        "text/csv",
        SENDGRID_BOUNCES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["mode"], "dry_run");
    // would-be writes: alice + bob (carol conflicts, the 4th row is invalid).
    assert_eq!(body["counts"]["imported"], 2, "would-be writes: {body}");
    assert_eq!(body["counts"]["duplicates"], 1, "carol conflicts: {body}");
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(total, 1, "a dry run writes nothing");
    assert!(
        body.get("report_id").is_none() || body["report_id"].is_null(),
        "a dry run stores no report either: {body}"
    );

    // Commit: the manual row survives with its own reason and source.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions?mode=commit",
        "text/csv",
        SENDGRID_BOUNCES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["imported"], 2);
    assert_eq!(body["counts"]["duplicates"], 1);
    let (reason, source) = stored_source(&pool, &tenant, "carol@example.com")
        .await
        .expect("carol row");
    assert_eq!(reason, "complaint", "the manual row was not overwritten");
    assert_eq!(source, "manual");
    assert!(
        body["report_id"].is_string(),
        "a commit stores the report: {body}"
    );

    // The stored report is readable with the kind's read scope.
    let report_id = body["report_id"].as_str().expect("report id");
    let (status, stored) = env.get(&format!("/v1/import/reports/{report_id}")).await;
    assert_eq!(status, StatusCode::OK, "{stored}");
    assert_eq!(stored["counts"]["imported"], 2);
    let (status, list) = env.get("/v1/import/reports").await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list.as_array().map(Vec::len), Some(1));

    // Another tenant cannot read it (opaque 404) and cannot see it listed.
    let (other, _other_tenant) = fixture(&pool, "free", &["suppressions:read"]).await;
    let (status, body) = other.get(&format!("/v1/import/reports/{report_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, list) = other.get("/v1/import/reports").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().map(Vec::len), Some(0), "{list}");
}

#[tokio::test]
async fn malformed_suppression_files_are_refused_with_a_named_error() {
    let Some(pool) = crate::test_db::canonical_pool("imp_malformed").await else {
        return;
    };
    let (env, _tenant) = fixture(&pool, "free", &["suppressions:write", "contacts:write"]).await;

    // A CSV with no email column.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions?format=csv",
        "text/csv",
        b"name,created,reason\nAlice,2026-08-01,550\n",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no email column"),
        "the refusal must name the problem: {body}"
    );

    // Unterminated JSON.
    let (status, body) = post_file(
        &env,
        "/v1/import/postmark/suppressions?format=json",
        "application/json",
        br#"{"Bounces": [{"Email": "a@example.com""#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("unterminated"),
        "{body}"
    );

    // JSON with no records array at all.
    let (status, body) = post_file(
        &env,
        "/v1/import/mailgun/suppressions?format=json",
        "application/json",
        br#"{"message": "ok"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no array of records"),
        "{body}"
    );

    // An empty file.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions",
        "application/octet-stream",
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // An XLSX upload is refused by name (the importer reads CSV/JSON only).
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/suppressions",
        "application/octet-stream",
        b"PK\x03\x04\x14\x00fake-xlsx",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("XLSX"),
        "{body}"
    );

    // A source_type from another provider's vocabulary is refused by name.
    let (status, body) = post_file(
        &env,
        "/v1/import/resend/suppressions?source_type=bounces",
        "text/csv",
        RESEND_SUPPRESSIONS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("source_type"),
        "{body}"
    );
}

#[tokio::test]
async fn import_requires_the_kinds_write_scope() {
    let Some(pool) = crate::test_db::canonical_pool("imp_scopes").await else {
        return;
    };
    // A key with only the read scopes: every kind's write must be refused.
    let (env, _tenant) = fixture(
        &pool,
        "free",
        &[
            "suppressions:read",
            "contacts:read",
            "templates:read",
            "domains:read",
        ],
    )
    .await;
    for (uri, content_type, body) in [
        (
            "/v1/import/sendgrid/suppressions?mode=commit",
            "text/csv",
            SENDGRID_BOUNCES_CSV.as_bytes(),
        ),
        (
            "/v1/import/sendgrid/contacts?mode=commit",
            "text/csv",
            SENDGRID_CONTACTS_CSV.as_bytes(),
        ),
        (
            "/v1/import/postmark/templates?mode=commit",
            "application/json",
            POSTMARK_TEMPLATES_JSON.as_bytes(),
        ),
    ] {
        let (status, response) = post_file(&env, uri, content_type, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} must be refused without its write scope: {response}"
        );
    }

    // An unknown provider or kind is a named 400, never a 404 surprise.
    let (status, body) = post_file(
        &env,
        "/v1/import/mailchimp/suppressions",
        "text/csv",
        b"email\nx@example.com\n",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("unknown provider"));
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/invoices",
        "text/csv",
        b"email\nx@example.com\n",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("unknown kind"));
}

// ─── Contacts: four providers, presets on the canonical import engine ─

#[tokio::test]
async fn sendgrid_contacts_preset_maps_names_and_flags_unsubscribed() {
    let Some(pool) = crate::test_db::canonical_pool("imp_c_sg").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["contacts:write"]).await;

    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/contacts?mode=commit",
        "text/csv",
        SENDGRID_CONTACTS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["rows"], 2);
    assert_eq!(body["counts"]["imported"], 2, "{body}");
    assert!(
        body["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap_or_default()
                .contains("marked unsubscribed")),
        "the unsubscribe signal must be named, never silent: {body}"
    );
    assert!(
        body["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap_or_default()
                .contains("address_line_1")),
        "ignored provider columns are named: {body}"
    );

    let (name, status): (Option<String>, String) =
        sqlx::query_as("SELECT name, status FROM contacts WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind("mira@example.com")
            .fetch_one(&pool)
            .await
            .expect("mira row");
    assert_eq!(name.as_deref(), Some("Mira Van der Berg"));
    assert_eq!(status, "active");
    let (name,): (Option<String>,) =
        sqlx::query_as("SELECT name FROM contacts WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind("noah@example.com")
            .fetch_one(&pool)
            .await
            .expect("noah row");
    assert_eq!(name.as_deref(), Some("Noah Smith"));

    // Replay: the canonical upsert is idempotent by (tenant_id, email).
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/contacts?mode=commit",
        "text/csv",
        SENDGRID_CONTACTS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(total, 2, "a replay never duplicates contacts");
}

#[tokio::test]
async fn mailgun_postmark_and_resend_contacts_presets() {
    let Some(pool) = crate::test_db::canonical_pool("imp_c_rest").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["contacts:write"]).await;

    let (status, body) = post_file(
        &env,
        "/v1/import/mailgun/contacts?mode=commit",
        "application/json",
        MAILGUN_CONTACTS_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["imported"], 2, "{body}");
    let (name,): (Option<String>,) =
        sqlx::query_as("SELECT name FROM contacts WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind("olive@example.com")
            .fetch_one(&pool)
            .await
            .expect("olive row");
    assert_eq!(name.as_deref(), Some("Olive Black"));
    assert!(
        !body["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap_or_default().contains("pete@")),
        "warnings never echo addresses: {body}"
    );

    let (status, body) = post_file(
        &env,
        "/v1/import/postmark/contacts?mode=commit",
        "text/csv",
        POSTMARK_CONTACTS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (name,): (Option<String>,) =
        sqlx::query_as("SELECT name FROM contacts WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind("quinn@example.com")
            .fetch_one(&pool)
            .await
            .expect("quinn row");
    assert_eq!(name.as_deref(), Some("Quinn Adams"));

    let (status, body) = post_file(
        &env,
        "/v1/import/resend/contacts?mode=commit",
        "application/json",
        RESEND_CONTACTS_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (name,): (Option<String>,) =
        sqlx::query_as("SELECT name FROM contacts WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind("sam@example.com")
            .fetch_one(&pool)
            .await
            .expect("sam row");
    assert_eq!(name.as_deref(), Some("Sam Cole"));

    // Dry run: the same validation without any write.
    let (status, body) = post_file(
        &env,
        "/v1/import/resend/contacts",
        "application/json",
        RESEND_CONTACTS_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["mode"], "dry_run");
    assert_eq!(body["counts"]["imported"], 2, "{body}");
    assert_eq!(
        body["counts"]["duplicates"], 0,
        "an existing contact is an UPDATE on the canonical upsert, not a duplicate: {body}"
    );
    assert!(
        body["conflicts"]
            .as_array()
            .expect("conflicts")
            .iter()
            .any(|note| note["note"]
                .as_str()
                .unwrap_or_default()
                .contains("would be updated")),
        "the dry run names the existing contacts it would update: {body}"
    );

    // The wrong format for a provider's export is a named refusal.
    let (status, body) = post_file(
        &env,
        "/v1/import/mailgun/contacts",
        "text/csv",
        b"email,name\nsomeone@example.com,Someone\n",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("JSON"));
}

// ─── Templates: conversion, needs_review, dry run ──────────────

#[tokio::test]
async fn sendgrid_templates_convert_safely_and_mark_unconvertible_ones() {
    let Some(pool) = crate::test_db::canonical_pool("imp_t_sg").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "growth", &["templates:write", "templates:read"]).await;

    // Dry run first: nothing is created, conversions are still reported.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/templates",
        "application/json",
        SENDGRID_TEMPLATES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["rows"], 2);
    assert_eq!(body["counts"]["imported"], 2, "would-be imports: {body}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM templates WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "a dry run creates no template rows");
    let welcome = &body["templates"][0];
    assert_eq!(welcome["status"], "would_import");
    assert_eq!(welcome["needs_review"], false, "{body}");
    assert!(
        welcome["conversions"]
            .as_array()
            .expect("conversions")
            .iter()
            .any(|note| note["construct"]
                .as_str()
                .unwrap_or_default()
                .contains("{{ first_name }}")),
        "the whitespace trim is a NAMED conversion: {welcome}"
    );

    // Commit.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/templates?mode=commit",
        "application/json",
        SENDGRID_TEMPLATES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["imported"], 2);
    assert_eq!(body["counts"]["needs_review"], 1, "{body}");

    // Template 1: converted, active, renders through the canonical renderer.
    let welcome_row = &body["templates"][0];
    assert_eq!(welcome_row["status"], "imported");
    let welcome_id = welcome_row["template_id"].as_str().expect("id").to_string();
    let (status, rendered) = env
        .post(
            &format!("/v1/templates/{welcome_id}/render"),
            &json!({"variables": {"first_name": "Ada"}}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{rendered}");
    assert_eq!(rendered["subject"], "Welcome Ada");
    assert_eq!(
        rendered["html"],
        "<h1>Hello Ada</h1><p>We are glad you are here.</p>"
    );

    // Template 2: the {{#each}} block is NOT converted (kept verbatim), the
    // triple-brace tag is converted with a named semantic warning, and the
    // row is marked needs_review — nothing was silently mangled.
    let receipt = &body["templates"][1];
    assert_eq!(receipt["needs_review"], true, "{body}");
    assert!(
        receipt["unconverted"]
            .as_array()
            .expect("unconverted")
            .iter()
            .any(|entry| entry
                .as_str()
                .unwrap_or_default()
                .contains("{{#each items}}")),
        "the block helper must be listed verbatim: {receipt}"
    );
    assert!(
        receipt["conversions"]
            .as_array()
            .expect("conversions")
            .iter()
            .any(|note| note["construct"]
                .as_str()
                .unwrap_or_default()
                .contains("{{{raw_note}}}")),
        "the triple-brace change must be named: {receipt}"
    );
    assert!(
        receipt["original_body"]
            .as_str()
            .expect("original body")
            .contains("{{#each items}}"),
        "the provider's original body is kept for review: {receipt}"
    );
    let receipt_id = receipt["template_id"].as_str().expect("id");
    let (status, stored) = env.get(&format!("/v1/templates/{receipt_id}")).await;
    assert_eq!(status, StatusCode::OK, "{stored}");
    assert_eq!(
        stored["status"], "needs_review",
        "the review marker lives on the canonical row: {stored}"
    );
    assert!(
        stored["html_body"]
            .as_str()
            .expect("body")
            .contains("{{#each items}}"),
        "the unconvertible construct is kept verbatim in the stored body: {stored}"
    );
    assert!(
        stored["html_body"]
            .as_str()
            .expect("body")
            .contains("{{raw_note}}"),
        "the triple-brace tag was converted to the escaped form: {stored}"
    );

    // Replay: existing names are skipped, never duplicated.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/templates?mode=commit",
        "application/json",
        SENDGRID_TEMPLATES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["imported"], 0);
    assert_eq!(body["counts"]["duplicates"], 2);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM templates WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count, 2);
}

#[tokio::test]
async fn sendgrid_legacy_and_mailgun_postmark_resend_templates_import() {
    let Some(pool) = crate::test_db::canonical_pool("imp_t_rest").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "growth", &["templates:write"]).await;

    // SendGrid legacy [%tag%] dialect.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/templates?mode=commit",
        "application/json",
        SENDGRID_LEGACY_TEMPLATES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["imported"], 1, "{body}");
    let (html,): (String,) = sqlx::query_as(
        "SELECT html_body FROM templates WHERE tenant_id = $1 AND name = 'legacy-hello'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("legacy row");
    assert_eq!(html, "<p>Hello {{first_name}}</p>");

    // Mailgun Go-style dotted path.
    let (status, body) = post_file(
        &env,
        "/v1/import/mailgun/templates?mode=commit",
        "application/json",
        MAILGUN_TEMPLATES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (html,): (String,) = sqlx::query_as(
        "SELECT html_body FROM templates WHERE tenant_id = $1 AND name = 'mailgun-welcome'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("mailgun row");
    assert_eq!(html, "<p>Hi {{name}}</p>");

    // Postmark (Name/Subject/HtmlBody/TextBody).
    let (status, body) = post_file(
        &env,
        "/v1/import/postmark/templates?mode=commit",
        "application/json",
        POSTMARK_TEMPLATES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (html, text, subject): (String, Option<String>, String) = sqlx::query_as(
        "SELECT html_body, text_body, subject FROM templates \
         WHERE tenant_id = $1 AND name = 'postmark-welcome'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("postmark row");
    assert_eq!(html, "<p>Hello {{name}}</p>");
    assert_eq!(text.as_deref(), Some("Hello {{name}}"));
    assert_eq!(subject, "Welcome");

    // Resend triple-brace syntax: converted with a named review marker.
    let (status, body) = post_file(
        &env,
        "/v1/import/resend/templates?mode=commit",
        "application/json",
        RESEND_TEMPLATES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["needs_review"], 1, "{body}");
    assert_eq!(body["templates"][0]["needs_review"], true);
    let (html,): (String,) = sqlx::query_as(
        "SELECT html_body FROM templates WHERE tenant_id = $1 AND name = 'resend-welcome'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("resend row");
    assert_eq!(html, "<p>Hi {{NAME}}</p>");

    // Malformed template JSON: named refusal.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/templates?format=json",
        "application/json",
        br#"{"templates": [{"name": "broken", "#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A template element with no body is a named per-row failure.
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/templates?mode=commit",
        "application/json",
        br#"{"templates": [{"name": "no-body", "subject": "s"}]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["counts"]["failed"], 1);
    assert_eq!(body["templates"][0]["status"], "failed");
    assert!(
        body["templates"][0]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no HTML body"),
        "{body}"
    );
}

/// The custom_templates entitlement is the canonical create path's gate: the
/// importer must refuse on the free plan exactly like POST /v1/templates.
#[tokio::test]
async fn template_import_on_the_free_plan_is_refused_by_the_entitlement() {
    let Some(pool) = crate::test_db::canonical_pool("imp_t_entitlement").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["templates:write"]).await;
    let (status, body) = post_file(
        &env,
        "/v1/import/postmark/templates?mode=commit",
        "application/json",
        POSTMARK_TEMPLATES_JSON.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM templates WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count, 0);
}

// ─── Domains: read-only report per provider ────────────────────

async fn seed_domain(pool: &PgPool, tenant: &str, name: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified,
             dkim_selector, dkim_public_key, dkim_private_key)
         VALUES ($1::uuid, $2, $3, 'verified', true, true, true, 'am-testselector', 'test-public-key', 'dkim:v1:test')",
    )
    .bind(&id)
    .bind(tenant)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed domain");
    id
}

#[tokio::test]
async fn domains_report_is_generated_per_provider_and_read_only() {
    let Some(pool) = crate::test_db::canonical_pool("imp_domains").await else {
        return;
    };
    let (env, tenant) = fixture(&pool, "free", &["domains:read"]).await;
    let domain_id = seed_domain(&pool, &tenant, "switch.example.com").await;

    for provider in ["sendgrid", "mailgun", "postmark", "resend"] {
        let (status, body) = post_file(
            &env,
            &format!("/v1/import/{provider}/domains?domain=switch.example.com"),
            "application/json",
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{provider}: {body}");
        assert_eq!(body["domain"]["from_provider"], provider);
        // KEEP: our required records, straight from the domains module.
        let keep: Vec<String> = body["domain"]["keep"]
            .as_array()
            .expect("keep")
            .iter()
            .map(|row| row["hostname"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(
            keep.contains(&"am-testselector._domainkey.switch.example.com".to_string()),
            "{provider}: DKIM keep record: {keep:?}"
        );
        assert!(keep.contains(&"_dmarc.switch.example.com".to_string()));
        assert!(
            body["domain"]["keep"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["action"] == "keep"),
            "{provider}: keep rows"
        );
        // DELETE candidates are the provider's own patterns.
        let note = body["domain"]["delete_candidates"]
            .as_array()
            .expect("delete")
            .iter()
            .map(|row| {
                format!(
                    "{} {}",
                    row["hostname"].as_str().unwrap_or(""),
                    row["value"].as_str().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join(" | ");
        let expected_marker = match provider {
            "sendgrid" => "sendgrid.net",
            "mailgun" => "mailgun.org",
            "postmark" => "pm.mtasv.net",
            _ => "amazonses.com",
        };
        assert!(
            note.contains(expected_marker),
            "{provider}: delete candidates must name the provider's host: {note}"
        );
        // EDITS: the shared SPF record, per provider include.
        let edits = body["domain"]["edits"]
            .as_array()
            .expect("edits")
            .iter()
            .map(|row| row["value"].as_str().unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join(" | ");
        let expected_include = match provider {
            "sendgrid" => "include:sendgrid.net",
            "mailgun" => "include:mailgun.org",
            "postmark" => "include:spf.mtasv.net",
            _ => "include:amazonses.com",
        };
        assert!(
            edits.contains(expected_include),
            "{provider}: the SPF edit must name the include: {edits}"
        );
        assert!(
            body["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .any(|warning| warning.as_str().unwrap_or_default().contains("read-only")),
            "{provider}: the read-only contract is stated: {body}"
        );
        assert_eq!(body["counts"]["imported"], 0);
    }

    // The query accepts an id OR a name, and the id arm now binds the
    // domains.id UUID natively (`id = $3::uuid`, primary key) instead of
    // casting the column with `id::text = $2`: resolving by id must behave
    // exactly like resolving by name, and an unknown id that parses as a UUID
    // (or a name that is neither) is still the same 404.
    let (status, by_id) = post_file(
        &env,
        &format!("/v1/import/sendgrid/domains?domain={domain_id}"),
        "application/json",
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resolution by id: {by_id}");
    assert_eq!(by_id["domain"]["from_provider"], "sendgrid");
    assert!(by_id["domain"]["keep"]
        .as_array()
        .expect("keep")
        .iter()
        .any(|row| row["hostname"] == "am-testselector._domainkey.switch.example.com"));
    let (status, body) = post_file(
        &env,
        &format!(
            "/v1/import/sendgrid/domains?domain={}",
            uuid::Uuid::new_v4()
        ),
        "application/json",
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unknown uuid id: {body}");
    let (status, body) = post_file(
        &env,
        "/v1/import/sendgrid/domains?domain=not-a-uuid-and-not-a-domain",
        "application/json",
        b"",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-UUID query that names no domain is the same 404: {body}"
    );

    // Ambiguity is impossible: a domain outside the tenant is a 404, and a
    // missing ?domain= is a named 400.
    let (other, _other_tenant) = fixture(&pool, "free", &["domains:read"]).await;
    let (status, body) = post_file(
        &other,
        "/v1/import/sendgrid/domains?domain=switch.example.com",
        "application/json",
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) =
        post_file(&env, "/v1/import/sendgrid/domains", "application/json", b"").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

// ─── Engine unit tests (no database) ──────────────────────────

#[test]
fn json_array_cursor_handles_envelopes_strings_and_bare_arrays() {
    use super::json_array_cursor;

    let bare = br#"[{"a": 1}, {"a": 2}]"#;
    let mut cursor = json_array_cursor(bare).expect("bare array");
    assert_eq!(cursor.envelope_key, None);
    let elements: Vec<&[u8]> =
        std::iter::from_fn(|| cursor.next_element().ok().flatten()).collect();
    assert_eq!(elements, vec![b"{\"a\": 1}".as_slice(), b"{\"a\": 2}"]);

    // Envelope key detection with a string containing a bracket BEFORE the
    // array (the string-aware scan must not mistake it for the array).
    let envelope = br#"{"note": "use [x] here", "items": [{"address": "a@example.com"}]}"#;
    let mut cursor = json_array_cursor(envelope).expect("envelope");
    assert_eq!(cursor.envelope_key.as_deref(), Some("items"));
    let element = cursor.next_element().expect("scan").expect("element");
    assert!(std::str::from_utf8(element)
        .unwrap()
        .contains("a@example.com"));

    // Escaped quotes and nested structures inside elements.
    let nested = br#"[{"x": "a \"quoted\" [bracket]", "y": [1, 2, 3]}]"#;
    let mut cursor = json_array_cursor(nested).expect("nested");
    let element = cursor.next_element().expect("scan").expect("element");
    assert!(std::str::from_utf8(element).unwrap().ends_with("3]}"));

    // Malformed: unterminated array, and no array at all.
    assert!(super::json_array_cursor(b"[{\"a\": 1}").is_err());
    assert!(super::json_array_cursor(br#"{"message": "ok"}"#).is_err());
}

#[test]
fn timestamp_parsing_is_honest_about_unknown_shapes() {
    use super::parse_timestamp;
    assert_eq!(
        parse_timestamp("2026-08-01T10:00:00Z").map(|ts| ts.to_rfc3339()),
        Some("2026-08-01T10:00:00+00:00".into())
    );
    assert_eq!(
        parse_timestamp("2026-08-01 10:00:00").map(|ts| ts.to_rfc3339()),
        Some("2026-08-01T10:00:00+00:00".into())
    );
    assert!(parse_timestamp("last tuesday").is_none());
    assert!(parse_timestamp("").is_none());
}
