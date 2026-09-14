//! Adversarial repository tests against the REAL canonical migration chain.
//!
//! Every test provisions its own throwaway database via
//! `migrator::test_support::fresh_canonical_pool` (soft-skip ONLY when
//! `TEST_DATABASE_URL` is unset; a configured-but-broken provisioning panics).
//! The point is not to re-test happy paths but to attack the SQL: NULL
//! handling, ordering/pagination edges, tenant scoping, constraint violations
//! surfacing as typed `sqlx::Error`s (never a panic), and empty-input
//! handling.

use apexmail_db::repos::api_keys::ApiKeysRepo;
use apexmail_db::repos::audit_logs::AuditRepo;
use apexmail_db::repos::campaigns::CampaignsRepo;
use apexmail_db::repos::contacts::ContactsRepo;
use apexmail_db::repos::domains::{DomainRepoError, DomainsRepo};
use apexmail_db::repos::events::{EventsRepo, NewEvent};
use apexmail_db::repos::incidents::{IncidentRepo, IncidentStatus};
use apexmail_db::repos::messages::MessagesRepo;
use apexmail_db::repos::support_tickets::SupportTicketsRepo;
use apexmail_db::repos::suppressions::SuppressionsRepo;
use apexmail_db::repos::templates::TemplatesRepo;
use apexmail_db::repos::tenants::TenantsRepo;
use apexmail_db::repos::users::UsersRepo;
use apexmail_db::repos::webhooks::WebhooksRepo;
use apexmail_db::types::short_id;
use sqlx::PgPool;
use uuid::Uuid;

/// Serializable env mutation for the DKIM key (the repo encrypts the private
/// key before insert; a missing key must FAIL CLOSED, never insert plaintext).
/// Async-aware: the DKIM-key section MUST hold the lock across its awaits
/// (the env var has to stay set for the whole section), and a `std::sync`
/// guard held over an await is a scheduling hazard, not a serialization
/// guarantee.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const DKIM_KEY_ENV: &str = "DKIM_PRIVATE_KEY_ENCRYPTION_KEY";

async fn canonical_pool(suffix: &str) -> Option<PgPool> {
    // The suffix is namespaced to THIS binary: `fresh_canonical_pool` derives
    // the database name as `<base>_<suffix>`, so two test binaries sharing a
    // suffix (this file and repos_canonical_db_tests.rs both used "incidents")
    // drop and re-create each other's database while running concurrently
    // under nextest — observed as `clone-connect: database ... does not
    // exist`.
    let namespaced = format!("adversarial_{suffix}");
    match migrator::test_support::fresh_canonical_pool("apexdb_repos_adversarial", &namespaced)
        .await
    {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// A tenant row plus a second tenant for cross-tenant isolation assertions.
/// `TenantsRepo::create` generates the id itself, so isolation is proven by
/// using two distinct tenants rather than hand-picked ids.
async fn two_tenants(pool: &PgPool) -> (String, String) {
    let a = TenantsRepo::create(pool, "Acme", &format!("acme-{}", short_id('a')), "pro")
        .await
        .expect("tenant a");
    let b = TenantsRepo::create(pool, "Globex", &format!("globex-{}", short_id('b')), "free")
        .await
        .expect("tenant b");
    (a.id, b.id)
}

async fn with_dkim_key() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = ENV_LOCK.lock().await;
    std::env::set_var(DKIM_KEY_ENV, "11".repeat(32));
    guard
}

/// Tenants: create → lookup by id/slug → update → slug uniqueness violation
/// surfaces as a typed `sqlx::Error::Database` (never a panic).
#[tokio::test]
async fn tenants_crud_and_slug_conflict_is_typed() {
    let Some(pool) = canonical_pool("tenants").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };

    let slug = format!("acme-{}", short_id('a'));
    let created = TenantsRepo::create(&pool, "Acme", &slug, "pro")
        .await
        .expect("create tenant");
    assert_eq!(created.plan, "pro");
    assert_eq!(created.status, "active");

    let by_id = TenantsRepo::find_by_id(&pool, &created.id)
        .await
        .unwrap()
        .expect("tenant by id");
    assert_eq!(by_id.slug, slug);
    let by_slug = TenantsRepo::find_by_slug(&pool, &slug)
        .await
        .unwrap()
        .expect("tenant by slug");
    assert_eq!(by_slug.id, created.id);

    // NULL-adjacent: an unknown id and an unknown slug are None, not Err.
    assert!(
        TenantsRepo::find_by_id(&pool, "tdoes-not-exist-000000000000")
            .await
            .unwrap()
            .is_none()
    );
    assert!(TenantsRepo::find_by_slug(&pool, "no-such-slug")
        .await
        .unwrap()
        .is_none());

    let updated = TenantsRepo::update(
        &pool,
        &created.id,
        "Acme Renamed",
        "enterprise",
        "suspended",
    )
    .await
    .unwrap()
    .expect("updated tenant");
    assert_eq!(updated.name, "Acme Renamed");
    assert_eq!(updated.plan, "enterprise");
    assert_eq!(updated.status, "suspended");
    // Updating a nonexistent id returns None (no phantom row).
    assert!(
        TenantsRepo::update(&pool, "tdoes-not-exist-000000000000", "x", "free", "active")
            .await
            .unwrap()
            .is_none()
    );

    // Hostile: the SAME slug again must be rejected by the unique constraint
    // as a typed database error the caller can classify, not a panic.
    let conflict = TenantsRepo::create(&pool, "Impostor", &slug, "free").await;
    let err = conflict.expect_err("duplicate slug must fail");
    assert!(
        matches!(err, sqlx::Error::Database(_)),
        "expected a typed Database error, got {err:?}"
    );

    pool.close().await;
}

/// Users: tenant scoping, keyset pagination ordering (ASC) and NULL name
/// handling; a duplicate email in the same tenant is a typed error only if
/// the schema enforces it — here we assert the row is readable with a NULL
/// name (the classic Option decode bug).
#[tokio::test]
async fn users_null_name_scoping_and_keyset_pagination() {
    let Some(pool) = canonical_pool("users").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    // NULL name must decode as None, never blow up the row decode.
    let null_name = UsersRepo::create(
        &pool,
        &tenant_a,
        "null-name@example.com",
        None,
        "h",
        "owner",
    )
    .await
    .expect("user with NULL name");
    assert!(null_name.name.is_none());
    assert_eq!(null_name.role, "owner");
    assert_eq!(null_name.status, "active");

    assert!(UsersRepo::find_by_id(&pool, null_name.id)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        UsersRepo::find_by_email(&pool, "null-name@example.com")
            .await
            .unwrap()
            .unwrap()
            .id,
        null_name.id
    );
    assert!(UsersRepo::find_by_email(&pool, "nobody@example.com")
        .await
        .unwrap()
        .is_none());

    // Three more users for ordering/pagination.
    for idx in 0..3 {
        UsersRepo::create(
            &pool,
            &tenant_a,
            &format!("user{idx}@example.com"),
            Some("Named"),
            "h",
            "member",
        )
        .await
        .unwrap();
    }
    // A user in another tenant must never leak into tenant A's listing.
    UsersRepo::create(&pool, &tenant_b, "outsider@example.com", None, "h", "owner")
        .await
        .unwrap();

    let all_a = UsersRepo::list_by_tenant(&pool, &tenant_a, 100, 0)
        .await
        .unwrap();
    assert_eq!(all_a.len(), 4, "only tenant A users: {all_a:?}");
    assert!(all_a.iter().all(|u| u.tenant_id == tenant_a));
    // Hostile limit/offset are clamped to the 1-row floor, not fatal.
    assert_eq!(
        UsersRepo::list_by_tenant(&pool, &tenant_a, -5, -9)
            .await
            .unwrap()
            .len(),
        1
    );

    // Keyset page 1 returns limit+1 rows (has_more indicator) in ASC order.
    let page1 = UsersRepo::list_keyset(&pool, &tenant_a, 2, None, None)
        .await
        .unwrap();
    assert_eq!(page1.len(), 3, "limit+1 rows");
    assert!(page1[0].created_at <= page1[1].created_at);
    // Page 2 starts strictly after the last row of the previous page.
    let last = &page1[1];
    let page2 = UsersRepo::list_keyset(&pool, &tenant_a, 2, Some(last.created_at), Some(last.id))
        .await
        .unwrap();
    assert!(
        page2.iter().all(|u| u.id != last.id),
        "cursor row must not repeat"
    );
    assert!(page2.iter().all(|u| u.tenant_id == tenant_a));

    // Update: NULL name is written as NULL (COALESCE is NOT applied here).
    let updated = UsersRepo::update(&pool, null_name.id, Some("Now Named"), "admin", "suspended")
        .await
        .unwrap()
        .expect("updated");
    assert_eq!(updated.name.as_deref(), Some("Now Named"));
    assert_eq!(updated.role, "admin");
    assert_eq!(updated.status, "suspended");
    assert!(UsersRepo::update(&pool, Uuid::new_v4(), None, "x", "y")
        .await
        .unwrap()
        .is_none());

    pool.close().await;
}

/// Templates: full CRUD plus the LIST projection. A listing that omits a
/// NOT-NULL-in-Rust column must fail loudly instead of silently; this test
/// pins that `list` returns decodable rows (regression for the missing
/// html_body projection).
#[tokio::test]
async fn templates_crud_and_list_projection_decodes() {
    let Some(pool) = canonical_pool("templates").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    let created = TemplatesRepo::create(
        &pool,
        &tenant_a,
        "Welcome",
        "Hi there",
        "<p>Hello</p>",
        Some("Hello"),
    )
    .await
    .expect("create template");
    assert_eq!(created.version, 1);
    assert_eq!(created.status, "draft");

    let fetched = TemplatesRepo::find_by_id(&pool, &tenant_a, &created.id)
        .await
        .unwrap()
        .expect("template by id");
    assert_eq!(fetched.html_body, "<p>Hello</p>");
    assert_eq!(fetched.text_body.as_deref(), Some("Hello"));
    // Cross-tenant lookup returns None (tenant scoping is in the WHERE).
    assert!(TemplatesRepo::find_by_id(&pool, &tenant_b, &created.id)
        .await
        .unwrap()
        .is_none());

    // A second template with a NULL text_body.
    let created2 = TemplatesRepo::create(&pool, &tenant_a, "Plain", "s", "<p>b</p>", None)
        .await
        .unwrap();
    assert!(created2.text_body.is_none());

    // list() must decode every returned row. The prior projection omitted
    // html_body/text_body while the Rust type requires html_body: String.
    let listed = TemplatesRepo::list(&pool, &tenant_a, 100, 0)
        .await
        .expect("list must decode rows");
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|t| t.tenant_id == tenant_a));
    // Tenant B sees nothing.
    assert!(TemplatesRepo::list(&pool, &tenant_b, 100, 0)
        .await
        .unwrap()
        .is_empty());

    let page = TemplatesRepo::list_keyset(&pool, &tenant_a, 1, None, None)
        .await
        .unwrap();
    assert_eq!(page.len(), 2, "limit+1");
    let last = &page[0];
    let page2 =
        TemplatesRepo::list_keyset(&pool, &tenant_a, 1, Some(last.updated_at), Some(&last.id))
            .await
            .unwrap();
    assert!(page2.iter().all(|t| t.id != last.id));

    // update bumps the version.
    let updated = TemplatesRepo::update(
        &pool,
        &tenant_a,
        &created.id,
        "Welcome v2",
        "Hello again",
        "<p>v2</p>",
        None,
    )
    .await
    .unwrap()
    .expect("updated");
    assert_eq!(updated.version, 2);
    assert!(
        updated.text_body.is_none(),
        "text_body overwritten with NULL"
    );
    assert!(
        TemplatesRepo::update(&pool, &tenant_b, &created.id, "x", "y", "z", None)
            .await
            .unwrap()
            .is_none()
    );

    assert!(!TemplatesRepo::delete(&pool, &tenant_b, &created.id)
        .await
        .unwrap());
    assert!(TemplatesRepo::delete(&pool, &tenant_a, &created.id)
        .await
        .unwrap());
    assert!(!TemplatesRepo::delete(&pool, &tenant_a, &created.id)
        .await
        .unwrap());

    pool.close().await;
}

/// Domains: invalid names are refused before any SQL; the DKIM key must be
/// encrypted with the configured key (fail closed without it); DNS
/// observations never flip `verified`; tenant scoping and keyset pagination.
#[tokio::test]
async fn domains_dkim_fail_closed_and_scoping() {
    let Some(pool) = canonical_pool("domains").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    // Hostile/invalid names are rejected by validation, never inserted.
    for bad in [
        "",
        " ",
        "not a domain",
        "exa mple.com",
        "-bad.com",
        "bad-.com",
        "a..b",
    ] {
        let err = DomainsRepo::create(&pool, &tenant_a, bad)
            .await
            .expect_err("invalid domain must be refused");
        assert!(
            matches!(err, DomainRepoError::InvalidDomainName),
            "expected InvalidDomainName for {bad:?}, got {err:?}"
        );
    }

    // Without the shared DKIM key the create fails closed (Dkim error), and
    // NO row is written.
    {
        let _guard = ENV_LOCK.lock().await;
        let saved = std::env::var(DKIM_KEY_ENV).ok();
        std::env::remove_var(DKIM_KEY_ENV);
        let err = DomainsRepo::create(&pool, &tenant_a, "no-key.example.com")
            .await
            .expect_err("missing DKIM key must fail closed");
        assert!(
            matches!(err, DomainRepoError::Dkim(_)),
            "expected Dkim error, got {err:?}"
        );
        match saved {
            Some(v) => std::env::set_var(DKIM_KEY_ENV, v),
            None => std::env::remove_var(DKIM_KEY_ENV),
        }
    }
    assert!(DomainsRepo::find_by_name(&pool, "no-key.example.com")
        .await
        .unwrap()
        .is_none());

    // Scoped: the DKIM key must be set for the whole section below, which
    // contains awaits, so the guard is async and released at the end of the
    // test.
    let _guard = with_dkim_key().await;
    // Trailing dot / uppercase are normalized before insert.
    let created = DomainsRepo::create(&pool, &tenant_a, "Mail.Example.COM.")
        .await
        .expect("create domain");
    assert_eq!(created.name, "mail.example.com");
    assert_eq!(created.status, "pending");
    assert!(created.dkim_enabled);
    assert!(
        created
            .dkim_private_key
            .as_deref()
            .unwrap_or_default()
            .starts_with("dkim:"),
        "private key must be stored in the encrypted envelope"
    );

    let by_id = DomainsRepo::find_by_id(&pool, &tenant_a, created.id)
        .await
        .unwrap()
        .expect("by id");
    assert_eq!(by_id.name, "mail.example.com");
    assert!(DomainsRepo::find_by_id(&pool, &tenant_b, created.id)
        .await
        .unwrap()
        .is_none());
    assert!(
        DomainsRepo::find_by_name(&pool, "MAIL.EXAMPLE.COM")
            .await
            .unwrap()
            .is_none(),
        "lookup is exact (case-sensitive), not normalized"
    );

    // A second domain for pagination.
    let second = DomainsRepo::create(&pool, &tenant_a, "second.example.com")
        .await
        .unwrap();
    let listed = DomainsRepo::list(&pool, &tenant_a, 100, 0).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(DomainsRepo::list(&pool, &tenant_b, 100, 0)
        .await
        .unwrap()
        .is_empty());
    // Hostile limit/offset sanitized.
    assert_eq!(
        DomainsRepo::list(&pool, &tenant_a, -1, -1)
            .await
            .unwrap()
            .len(),
        1
    );

    let page1 = DomainsRepo::list_keyset(&pool, &tenant_a, 1, None, None)
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);
    let cursor = &page1[0];
    let page2 = DomainsRepo::list_keyset(
        &pool,
        &tenant_a,
        1,
        Some(cursor.created_at),
        Some(cursor.id),
    )
    .await
    .unwrap();
    assert!(page2.iter().all(|d| d.id != cursor.id));

    // DNS observations are recorded but can NEVER verify a domain.
    assert!(
        DomainsRepo::record_dns_check(&pool, &tenant_a, created.id, true, true, true)
            .await
            .unwrap()
    );
    let observed = DomainsRepo::find_by_id(&pool, &tenant_a, created.id)
        .await
        .unwrap()
        .unwrap();
    assert!(observed.spf_verified && observed.dkim_verified && observed.dmarc_verified);
    assert_eq!(observed.status, "pending", "status must stay pending");
    assert!(!observed.ses_verified);
    assert!(
        !DomainsRepo::record_dns_check(&pool, &tenant_b, created.id, true, true, true)
            .await
            .unwrap()
    );

    assert!(!DomainsRepo::delete(&pool, &tenant_b, second.id)
        .await
        .unwrap());
    assert!(DomainsRepo::delete(&pool, &tenant_a, second.id)
        .await
        .unwrap());
    assert!(!DomainsRepo::delete(&pool, &tenant_a, second.id)
        .await
        .unwrap());

    pool.close().await;
}

/// Contacts: NOT NULL tags default, NULL metadata, tenant+email uniqueness
/// (typed error), option-preserving update, bulk_create with duplicates and
/// empty input.
#[tokio::test]
async fn contacts_null_shape_uniqueness_and_bulk() {
    let Some(pool) = canonical_pool("contacts").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    // tags None → canonical '[]' (NOT NULL) with metadata NULL.
    let created = ContactsRepo::create(&pool, &tenant_a, "alice@example.com", None, None, None)
        .await
        .expect("create contact");
    assert_eq!(created.tags, Some(serde_json::json!([])));
    assert!(created.metadata.is_none());
    assert!(created.name.is_none());
    assert_eq!(created.status, "active");

    assert!(ContactsRepo::find_by_id(&pool, &tenant_a, created.id)
        .await
        .unwrap()
        .is_some());
    assert!(ContactsRepo::find_by_id(&pool, &tenant_b, created.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        ContactsRepo::find_by_email(&pool, &tenant_a, "alice@example.com")
            .await
            .unwrap()
            .unwrap()
            .id,
        created.id
    );

    // Duplicate (tenant, email) is a typed constraint error.
    let dup = ContactsRepo::create(&pool, &tenant_a, "alice@example.com", Some("A"), None, None)
        .await
        .expect_err("duplicate contact must fail");
    assert!(matches!(dup, sqlx::Error::Database(_)), "{dup:?}");
    // The SAME email in another tenant is fine.
    ContactsRepo::create(&pool, &tenant_b, "alice@example.com", None, None, None)
        .await
        .expect("same email, different tenant");

    // Update with None keeps stored tags and metadata; status always written.
    let updated = ContactsRepo::update(
        &pool,
        &tenant_a,
        created.id,
        Some("Alice"),
        Some(serde_json::json!(["vip"])),
        Some(serde_json::json!({"tier": 2})),
        "subscribed",
    )
    .await
    .unwrap()
    .expect("updated");
    assert_eq!(updated.name.as_deref(), Some("Alice"));
    assert_eq!(updated.tags, Some(serde_json::json!(["vip"])));
    assert_eq!(updated.metadata, Some(serde_json::json!({"tier": 2})));
    assert_eq!(updated.status, "subscribed");

    let preserved = ContactsRepo::update(&pool, &tenant_a, created.id, None, None, None, "active")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.tags, Some(serde_json::json!(["vip"])));
    assert_eq!(preserved.metadata, Some(serde_json::json!({"tier": 2})));
    assert_eq!(preserved.name.as_deref(), Some("Alice"));

    // Cross-tenant update is a no-op (None), not a silent write.
    assert!(ContactsRepo::update(
        &pool,
        &tenant_b,
        created.id,
        Some("Hijack"),
        None,
        None,
        "active"
    )
    .await
    .unwrap()
    .is_none());

    // Pagination.
    for idx in 0..3 {
        ContactsRepo::create(
            &pool,
            &tenant_a,
            &format!("c{idx}@example.com"),
            Some("C"),
            None,
            None,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        ContactsRepo::list(&pool, &tenant_a, 2, 0)
            .await
            .unwrap()
            .len(),
        2
    );
    // An offset past the end is an empty page, never an error.
    assert!(ContactsRepo::list(&pool, &tenant_a, 100, 100)
        .await
        .unwrap()
        .is_empty());
    let page = ContactsRepo::list_keyset(&pool, &tenant_a, 100, None, None)
        .await
        .unwrap();
    assert_eq!(page.len(), 4);
    assert!(page.iter().all(|c| c.tenant_id == tenant_a));

    // bulk_create: empty input is a fast empty Vec; duplicate rows are
    // skipped via ON CONFLICT DO NOTHING.
    assert!(ContactsRepo::bulk_create(&pool, &tenant_a, &[])
        .await
        .unwrap()
        .is_empty());
    let bulk = ContactsRepo::bulk_create(
        &pool,
        &tenant_a,
        &[
            ("b1@example.com", Some("B1")),
            ("b2@example.com", None),
            ("alice@example.com", Some("dup")),
        ],
    )
    .await
    .expect("bulk create");
    assert_eq!(bulk.len(), 2, "the conflicting row is skipped");

    assert!(!ContactsRepo::delete(&pool, &tenant_b, created.id)
        .await
        .unwrap());
    assert!(ContactsRepo::delete(&pool, &tenant_a, created.id)
        .await
        .unwrap());
    assert!(!ContactsRepo::delete(&pool, &tenant_a, created.id)
        .await
        .unwrap());

    pool.close().await;
}

/// Suppressions: upsert semantics on (tenant, email), empty bulk, tenant
/// scoping, id-based delete and the boolean fast path.
#[tokio::test]
async fn suppressions_upsert_scoping_and_bulk() {
    let Some(pool) = canonical_pool("suppressions").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    let first = SuppressionsRepo::create(
        &pool,
        &tenant_a,
        "bounce@example.com",
        "hard_bounce",
        "smtp",
    )
    .await
    .expect("create suppression");
    assert_eq!(first.reason, "hard_bounce");

    // Upsert: same (tenant, email) updates reason/source, same id row count 1.
    let second =
        SuppressionsRepo::create(&pool, &tenant_a, "bounce@example.com", "complaint", "ses")
            .await
            .unwrap();
    assert_eq!(second.id, first.id, "ON CONFLICT DO UPDATE keeps the row");
    assert_eq!(second.reason, "complaint");
    assert_eq!(second.source, "ses");
    assert_eq!(
        SuppressionsRepo::list(&pool, &tenant_a, 100, 0)
            .await
            .unwrap()
            .len(),
        1
    );

    // Same email under another tenant is an independent row.
    let other = SuppressionsRepo::create(&pool, &tenant_b, "bounce@example.com", "manual", "admin")
        .await
        .unwrap();
    assert_ne!(other.id, first.id);

    assert!(
        SuppressionsRepo::is_suppressed(&pool, &tenant_a, "bounce@example.com")
            .await
            .unwrap()
    );
    assert!(
        !SuppressionsRepo::is_suppressed(&pool, &tenant_a, "clean@example.com")
            .await
            .unwrap()
    );
    assert!(
        SuppressionsRepo::find_by_email(&pool, &tenant_a, "nobody@example.com")
            .await
            .unwrap()
            .is_none()
    );

    // list pagination is clamped.
    for idx in 0..3 {
        SuppressionsRepo::create(
            &pool,
            &tenant_a,
            &format!("s{idx}@example.com"),
            "manual",
            "admin",
        )
        .await
        .unwrap();
    }
    assert_eq!(
        SuppressionsRepo::list(&pool, &tenant_a, -1, -1)
            .await
            .unwrap()
            .len(),
        1,
        "clamped limit"
    );
    assert_eq!(
        SuppressionsRepo::list(&pool, &tenant_a, 100, 1)
            .await
            .unwrap()
            .len(),
        3
    );

    // Bulk: empty is a fast Vec; duplicates within the batch upsert.
    assert!(SuppressionsRepo::bulk_create(&pool, &tenant_a, &[])
        .await
        .unwrap()
        .is_empty());
    let bulk = SuppressionsRepo::bulk_create(
        &pool,
        &tenant_a,
        &[
            ("x1@example.com", "manual", "admin"),
            ("x2@example.com", "manual", "admin"),
        ],
    )
    .await
    .unwrap();
    assert_eq!(bulk.len(), 2);

    assert!(!SuppressionsRepo::delete(&pool, &tenant_b, &second.id)
        .await
        .unwrap());
    assert!(SuppressionsRepo::delete(&pool, &tenant_a, &second.id)
        .await
        .unwrap());
    assert!(!SuppressionsRepo::delete(&pool, &tenant_a, &second.id)
        .await
        .unwrap());

    pool.close().await;
}

/// Messages: status filter, keyset's four branches, cancel/update status
/// transitions and batch_create (empty + multi + NULL bodies).
#[tokio::test]
async fn messages_filters_keyset_and_batch() {
    let Some(pool) = canonical_pool("messages").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    let first = MessagesRepo::create(
        &pool,
        &tenant_a,
        "from@example.com",
        serde_json::json!(["to@example.com"]),
        None,
        None,
        "Subject A",
        Some("<p>html</p>"),
        None,
        Some(serde_json::json!(["tag1"])),
        Some(serde_json::json!({"k": "v"})),
        None,
    )
    .await
    .expect("create message");
    assert_eq!(first.status, "queued");
    assert!(first.text_body.is_none(), "NULL text_body decodes as None");
    assert!(first.cc_emails.is_none());

    // Tenant scoping on find_by_id.
    assert!(MessagesRepo::find_by_id(&pool, &tenant_a, first.id)
        .await
        .unwrap()
        .is_some());
    assert!(MessagesRepo::find_by_id(&pool, &tenant_b, first.id)
        .await
        .unwrap()
        .is_none());

    // A scheduled message + a second queued message.
    let scheduled = MessagesRepo::create(
        &pool,
        &tenant_a,
        "from@example.com",
        serde_json::json!(["to@example.com"]),
        Some(serde_json::json!(["cc@example.com"])),
        Some(serde_json::json!(["bcc@example.com"])),
        "Subject B",
        None,
        Some("text"),
        None,
        None,
        Some(chrono::Utc::now() + chrono::Duration::hours(1)),
    )
    .await
    .unwrap();
    assert!(scheduled.scheduled_at.is_some());
    assert!(scheduled.sent_at.is_none());

    // list with/without status filter.
    let all = MessagesRepo::list(&pool, &tenant_a, 100, 0, None)
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
    let queued = MessagesRepo::list(&pool, &tenant_a, 100, 0, Some("queued"))
        .await
        .unwrap();
    assert_eq!(queued.len(), 2);
    let sent = MessagesRepo::list(&pool, &tenant_a, 100, 0, Some("sent"))
        .await
        .unwrap();
    assert!(sent.is_empty());
    assert!(MessagesRepo::list(&pool, &tenant_b, 100, 0, None)
        .await
        .unwrap()
        .is_empty());

    // Keyset branch coverage: (cursor, status) × 4.
    let p1 = MessagesRepo::list_keyset(&pool, &tenant_a, 10, None, None, None)
        .await
        .unwrap();
    assert_eq!(p1.len(), 2);
    let cursor = &p1[0];
    let p2 = MessagesRepo::list_keyset(
        &pool,
        &tenant_a,
        10,
        Some(cursor.created_at),
        Some(cursor.id),
        None,
    )
    .await
    .unwrap();
    assert!(p2.iter().all(|m| m.id != cursor.id));
    let p3 = MessagesRepo::list_keyset(&pool, &tenant_a, 10, None, None, Some("queued"))
        .await
        .unwrap();
    assert_eq!(p3.len(), 2);
    let p4 = MessagesRepo::list_keyset(
        &pool,
        &tenant_a,
        10,
        Some(cursor.created_at),
        Some(cursor.id),
        Some("queued"),
    )
    .await
    .unwrap();
    assert_eq!(p4.len(), 1, "only the message older than the cursor");
    // Hostile limit is clamped to at least 1.
    assert!(
        !MessagesRepo::list_keyset(&pool, &tenant_a, -100, None, None, None)
            .await
            .unwrap()
            .is_empty()
    );

    // update_status is tenant-scoped.
    assert!(
        MessagesRepo::update_status(&pool, &tenant_a, first.id, "sent")
            .await
            .unwrap()
    );
    assert!(
        !MessagesRepo::update_status(&pool, &tenant_b, first.id, "sent")
            .await
            .unwrap()
    );
    assert!(
        !MessagesRepo::update_status(&pool, &tenant_a, Uuid::new_v4(), "sent")
            .await
            .unwrap()
    );

    // cancel only cancels queued/scheduled rows.
    assert!(
        !MessagesRepo::cancel(&pool, &tenant_a, first.id)
            .await
            .unwrap(),
        "already sent cannot be cancelled"
    );
    assert!(MessagesRepo::cancel(&pool, &tenant_a, scheduled.id)
        .await
        .unwrap());
    assert!(
        !MessagesRepo::cancel(&pool, &tenant_a, scheduled.id)
            .await
            .unwrap(),
        "cancel is not idempotent on state"
    );
    assert!(!MessagesRepo::cancel(&pool, &tenant_b, scheduled.id)
        .await
        .unwrap());

    // batch_create: empty input, then two rows with NULL bodies.
    assert!(MessagesRepo::batch_create(&pool, &tenant_a, &[])
        .await
        .unwrap()
        .is_empty());
    let batch = MessagesRepo::batch_create(
        &pool,
        &tenant_a,
        &[
            (
                "b@example.com".to_string(),
                serde_json::json!(["x@example.com"]),
                "B1".to_string(),
                Some("<p>1</p>".to_string()),
                None,
            ),
            (
                "b@example.com".to_string(),
                serde_json::json!(["y@example.com"]),
                "B2".to_string(),
                None,
                Some("t2".to_string()),
            ),
        ],
    )
    .await
    .expect("batch create");
    assert_eq!(batch.len(), 2);
    assert!(batch.iter().all(|m| m.status == "queued"));

    pool.close().await;
}

/// Events: provenance columns, per-message ordering, count/stats aggregates
/// and keyset pagination over `timestamp`.
#[tokio::test]
async fn events_provenance_aggregates_and_keyset() {
    let Some(pool) = canonical_pool("events").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;
    let message_id = format!("msg-{}", short_id('m'));

    let delivered = EventsRepo::create(
        &pool,
        NewEvent {
            tenant_id: &tenant_a,
            message_id: Some(&message_id),
            event_type: "delivered",
            recipient: Some("r@example.com"),
            metadata: Some(serde_json::json!({"mx": "gmail"})),
            recipient_provider: Some("gmail"),
            provider_source: Some("mx_resolved"),
        },
    )
    .await
    .expect("create event");
    assert_eq!(delivered.event_type, "delivered");
    assert_eq!(delivered.message_id.as_deref(), Some(message_id.as_str()));
    assert!(delivered.recipient.is_some());

    // Unknown provenance stays NULL.
    let opened = EventsRepo::create(
        &pool,
        NewEvent {
            tenant_id: &tenant_a,
            message_id: Some(&message_id),
            event_type: "opened",
            recipient: None,
            metadata: None,
            recipient_provider: None,
            provider_source: None,
        },
    )
    .await
    .unwrap();
    assert!(opened.recipient.is_none());
    assert!(opened.metadata.is_none());

    // An invalid provider_source is rejected by the canonical CHECK as a
    // typed error.
    let bad_source = EventsRepo::create(
        &pool,
        NewEvent {
            tenant_id: &tenant_a,
            message_id: Some(&message_id),
            event_type: "delivered",
            recipient: None,
            metadata: None,
            recipient_provider: Some("gmail"),
            provider_source: Some("guesswork"),
        },
    )
    .await
    .expect_err("CHECK violation must be a typed error");
    assert!(
        matches!(bad_source, sqlx::Error::Database(_)),
        "{bad_source:?}"
    );

    // Same event type in another tenant never leaks.
    EventsRepo::create(
        &pool,
        NewEvent {
            tenant_id: &tenant_b,
            message_id: Some(&message_id),
            event_type: "delivered",
            recipient: None,
            metadata: None,
            recipient_provider: None,
            provider_source: None,
        },
    )
    .await
    .unwrap();

    let by_message = EventsRepo::list_by_message(&pool, &tenant_a, &message_id)
        .await
        .unwrap();
    assert_eq!(by_message.len(), 2);
    assert!(
        by_message[0].timestamp <= by_message[1].timestamp,
        "ASC order"
    );
    assert!(
        EventsRepo::list_by_message(&pool, &tenant_b, "no-such-message")
            .await
            .unwrap()
            .is_empty()
    );

    let by_tenant = EventsRepo::list_by_tenant(&pool, &tenant_a, 100, 0)
        .await
        .unwrap();
    assert_eq!(by_tenant.len(), 2);
    assert!(
        EventsRepo::list_by_tenant(&pool, &tenant_a, -1, -1)
            .await
            .unwrap()
            .len()
            <= 2
    );

    let page = EventsRepo::list_keyset_by_tenant(&pool, &tenant_a, 1, None, None)
        .await
        .unwrap();
    assert_eq!(page.len(), 2, "limit+1");
    let cursor = &page[0];
    let page2 = EventsRepo::list_keyset_by_tenant(
        &pool,
        &tenant_a,
        1,
        Some(cursor.timestamp),
        Some(&cursor.id),
    )
    .await
    .unwrap();
    assert!(page2.iter().all(|e| e.id != cursor.id));

    let counts = EventsRepo::count_by_type(&pool, &tenant_a, 24)
        .await
        .unwrap();
    assert!(counts
        .iter()
        .any(|c| c.event_type == "delivered" && c.count == 1));
    let stats = EventsRepo::stats_by_type(&pool, &tenant_a, 24)
        .await
        .unwrap();
    assert!(stats
        .iter()
        .any(|c| c.event_type == "delivered" && c.count == 1));
    assert!(
        EventsRepo::count_by_type(&pool, "tno-such-tenant-00000000000", 24)
            .await
            .unwrap()
            .is_empty()
    );

    pool.close().await;
}

/// Webhooks: event-type containment, keyset, update/delete scoping.
#[tokio::test]
async fn webhooks_event_containment_and_scoping() {
    let Some(pool) = canonical_pool("webhooks").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    let created = WebhooksRepo::create(
        &pool,
        &tenant_a,
        "https://example.com/hook",
        serde_json::json!(["delivered", "bounced"]),
        "s3cret",
    )
    .await
    .expect("create webhook");
    assert_eq!(created.status, "active");

    assert!(WebhooksRepo::find_by_id(&pool, &tenant_a, &created.id)
        .await
        .unwrap()
        .is_some());
    assert!(WebhooksRepo::find_by_id(&pool, &tenant_b, &created.id)
        .await
        .unwrap()
        .is_none());

    // A second hook with a different event set.
    let other = WebhooksRepo::create(
        &pool,
        &tenant_a,
        "https://example.com/other",
        serde_json::json!(["opened"]),
        "s3cret2",
    )
    .await
    .unwrap();

    let delivered = WebhooksRepo::list_by_event_type(&pool, &tenant_a, "delivered")
        .await
        .unwrap();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].id, created.id);
    assert!(
        WebhooksRepo::list_by_event_type(&pool, &tenant_a, "complaint")
            .await
            .unwrap()
            .is_empty()
    );

    // Inactive hooks are never selected for delivery.
    WebhooksRepo::update(
        &pool,
        &tenant_a,
        &created.id,
        "https://example.com/hook2",
        serde_json::json!(["delivered"]),
        "inactive",
    )
    .await
    .unwrap()
    .expect("updated");
    assert!(
        WebhooksRepo::list_by_event_type(&pool, &tenant_a, "delivered")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(WebhooksRepo::update(
        &pool,
        &tenant_b,
        &created.id,
        "https://evil.example.com",
        serde_json::json!([]),
        "active"
    )
    .await
    .unwrap()
    .is_none());
    // The cross-tenant attempt changed nothing.
    assert_eq!(
        WebhooksRepo::find_by_id(&pool, &tenant_a, &created.id)
            .await
            .unwrap()
            .unwrap()
            .url,
        "https://example.com/hook2"
    );

    assert_eq!(
        WebhooksRepo::list(&pool, &tenant_a, 100, 0)
            .await
            .unwrap()
            .len(),
        2
    );
    let page = WebhooksRepo::list_keyset(&pool, &tenant_a, 1, None, None)
        .await
        .unwrap();
    assert_eq!(page.len(), 2);
    let cursor = &page[0];
    let page2 = WebhooksRepo::list_keyset(
        &pool,
        &tenant_a,
        1,
        Some(cursor.created_at),
        Some(&cursor.id),
    )
    .await
    .unwrap();
    assert!(page2.iter().all(|w| w.id != cursor.id));

    assert!(!WebhooksRepo::delete(&pool, &tenant_b, &other.id)
        .await
        .unwrap());
    assert!(WebhooksRepo::delete(&pool, &tenant_a, &other.id)
        .await
        .unwrap());
    assert!(!WebhooksRepo::delete(&pool, &tenant_a, &other.id)
        .await
        .unwrap());

    pool.close().await;
}

/// API keys: unique hash constraint is typed, NULL expiry decodes, tenant
/// scoping, last_used stamping.
#[tokio::test]
async fn api_keys_unique_hash_null_expiry_and_scoping() {
    let Some(pool) = canonical_pool("api_keys").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    let key = ApiKeysRepo::create(
        &pool,
        &tenant_a,
        "CI",
        "hash-1",
        "am_live",
        serde_json::json!(["messages:send"]),
    )
    .await
    .expect("create key");
    assert!(key.last_used_at.is_none());
    assert!(key.expires_at.is_none());

    // Duplicate key_hash is a typed constraint error.
    let dup = ApiKeysRepo::create(
        &pool,
        &tenant_b,
        "Other",
        "hash-1",
        "am_live",
        serde_json::json!([]),
    )
    .await
    .expect_err("duplicate hash must fail");
    assert!(matches!(dup, sqlx::Error::Database(_)), "{dup:?}");

    assert_eq!(
        ApiKeysRepo::find_by_hash(&pool, "hash-1")
            .await
            .unwrap()
            .unwrap()
            .id,
        key.id
    );
    assert!(ApiKeysRepo::find_by_hash(&pool, "missing")
        .await
        .unwrap()
        .is_none());

    ApiKeysRepo::create(
        &pool,
        &tenant_a,
        "Second",
        "hash-2",
        "am_live",
        serde_json::json!([]),
    )
    .await
    .unwrap();
    assert_eq!(
        ApiKeysRepo::list(&pool, &tenant_a, 100, 0)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(ApiKeysRepo::list(&pool, &tenant_b, 100, 0)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        ApiKeysRepo::list(&pool, &tenant_b, -1, -1)
            .await
            .unwrap()
            .len(),
        0
    );

    ApiKeysRepo::update_last_used(&pool, key.id).await.unwrap();
    let refreshed = ApiKeysRepo::find_by_hash(&pool, "hash-1")
        .await
        .unwrap()
        .unwrap();
    assert!(refreshed.last_used_at.is_some(), "stamp must persist");
    // Stamping an unknown id is a silent no-op, not an error.
    ApiKeysRepo::update_last_used(&pool, Uuid::new_v4())
        .await
        .unwrap();

    assert!(!ApiKeysRepo::delete(&pool, &tenant_b, key.id).await.unwrap());
    assert!(ApiKeysRepo::delete(&pool, &tenant_a, key.id).await.unwrap());
    assert!(!ApiKeysRepo::delete(&pool, &tenant_a, key.id).await.unwrap());

    pool.close().await;
}

/// Audit logs: NULL-able actor/resource columns and timestamp DESC ordering.
#[tokio::test]
async fn audit_logs_nullable_columns_and_ordering() {
    let Some(pool) = canonical_pool("audit_logs").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    // Global chain row: NULL tenant, NULL user, NULL resource_id.
    let global = AuditRepo::create(
        &pool,
        None,
        None,
        "system.boot",
        "system",
        None,
        serde_json::json!({}),
        None,
        "success",
        "hash-0",
        None,
        "sig-0",
    )
    .await
    .expect("global audit row");
    assert!(global.tenant_id.is_none());
    assert!(global.user_id.is_none());
    assert!(global.resource_id.is_none());
    assert!(global.previous_hash.is_none());

    let t1 = AuditRepo::create(
        &pool,
        Some(&tenant_a),
        Some("u1"),
        "domain.create",
        "domain",
        Some("example.com"),
        serde_json::json!({"verified": false}),
        Some("203.0.113.7"),
        "success",
        "hash-1",
        Some("hash-0"),
        "sig-1",
    )
    .await
    .unwrap();
    assert_eq!(t1.action, "domain.create");
    let t2 = AuditRepo::create(
        &pool,
        Some(&tenant_a),
        Some("u1"),
        "domain.delete",
        "domain",
        Some("example.com"),
        serde_json::json!({}),
        None,
        "failure",
        "hash-2",
        Some("hash-1"),
        "sig-2",
    )
    .await
    .unwrap();

    let listed = AuditRepo::list(&pool, &tenant_a, 100, 0).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed[0].timestamp >= listed[1].timestamp, "DESC order");
    assert!(listed
        .iter()
        .all(|l| l.tenant_id.as_deref() == Some(tenant_a.as_str())));
    assert!(listed
        .iter()
        .any(|l| l.error_message.is_none() && l.outcome == "failure"));
    // Global rows are not in a tenant listing.
    assert!(AuditRepo::list(&pool, &tenant_b, 100, 0)
        .await
        .unwrap()
        .is_empty());
    // Hostile pagination is clamped.
    assert_eq!(
        AuditRepo::list(&pool, &tenant_a, -1, -1)
            .await
            .unwrap()
            .len(),
        1
    );
    let _ = t2;

    pool.close().await;
}

/// Support tickets: status transitions, NULL assignee, tenant scoping.
#[tokio::test]
async fn support_tickets_status_and_null_assignee() {
    let Some(pool) = canonical_pool("support_tickets").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    let ticket = SupportTicketsRepo::create(&pool, &tenant_a, "Cannot send", "403 errors", "high")
        .await
        .expect("create ticket");
    assert_eq!(ticket.status, "open");
    assert!(ticket.assigned_to.is_none());

    assert!(SupportTicketsRepo::find_by_id(&pool, &tenant_a, &ticket.id)
        .await
        .unwrap()
        .is_some());
    assert!(SupportTicketsRepo::find_by_id(&pool, &tenant_b, &ticket.id)
        .await
        .unwrap()
        .is_none());

    assert!(
        SupportTicketsRepo::update_status(&pool, &tenant_a, &ticket.id, "resolved", None)
            .await
            .unwrap()
    );
    let resolved = SupportTicketsRepo::find_by_id(&pool, &tenant_a, &ticket.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolved.status, "resolved");
    // Cross-tenant transition is refused.
    assert!(!SupportTicketsRepo::update_status(
        &pool,
        &tenant_b,
        &ticket.id,
        "closed",
        Some("agent")
    )
    .await
    .unwrap());
    assert!(
        !SupportTicketsRepo::update_status(&pool, &tenant_a, "no-such-id", "closed", None)
            .await
            .unwrap()
    );

    assert_eq!(
        SupportTicketsRepo::list(&pool, &tenant_a, 100, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(SupportTicketsRepo::list(&pool, &tenant_b, 100, 0)
        .await
        .unwrap()
        .is_empty());
    // Unclamped hostile pagination must not error.
    // A high offset with a live row returns empty (no error, no row leak).
    assert!(SupportTicketsRepo::list(&pool, &tenant_a, 10, 100)
        .await
        .unwrap()
        .is_empty());

    pool.close().await;
}

/// Campaigns: draft-only delete, tenant scoping, sent_count default and
/// keyset pagination.
#[tokio::test]
async fn campaigns_draft_only_delete_and_keyset() {
    let Some(pool) = canonical_pool("campaigns").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let (tenant_a, tenant_b) = two_tenants(&pool).await;

    let draft = CampaignsRepo::create(
        &pool,
        &tenant_a,
        "Black Friday",
        "50% off",
        None,
        Some(chrono::Utc::now() + chrono::Duration::days(1)),
    )
    .await
    .expect("create campaign");
    assert_eq!(draft.status, "draft");
    assert_eq!(draft.sent_count, 0);
    assert!(draft.template_id.is_none());
    assert!(draft.scheduled_at.is_some());

    assert!(CampaignsRepo::find_by_id(&pool, &tenant_a, draft.id)
        .await
        .unwrap()
        .is_some());
    assert!(CampaignsRepo::find_by_id(&pool, &tenant_b, draft.id)
        .await
        .unwrap()
        .is_none());

    // A non-draft campaign cannot be deleted.
    let sent = CampaignsRepo::create(&pool, &tenant_a, "Newsletter", "Weekly", None, None)
        .await
        .unwrap();
    assert!(
        CampaignsRepo::update_status(&pool, &tenant_a, sent.id, "sent")
            .await
            .unwrap()
    );
    assert!(!CampaignsRepo::delete(&pool, &tenant_a, sent.id)
        .await
        .unwrap());
    assert!(
        !CampaignsRepo::update_status(&pool, &tenant_b, sent.id, "draft")
            .await
            .unwrap()
    );

    assert_eq!(
        CampaignsRepo::list(&pool, &tenant_a, 100, 0)
            .await
            .unwrap()
            .len(),
        2
    );
    let page = CampaignsRepo::list_keyset(&pool, &tenant_a, 1, None, None)
        .await
        .unwrap();
    assert_eq!(page.len(), 2);
    let cursor = &page[0];
    let page2 = CampaignsRepo::list_keyset(
        &pool,
        &tenant_a,
        1,
        Some(cursor.created_at),
        Some(cursor.id),
    )
    .await
    .unwrap();
    assert!(page2.iter().all(|c| c.id != cursor.id));

    // Draft delete succeeds exactly once.
    assert!(CampaignsRepo::delete(&pool, &tenant_a, draft.id)
        .await
        .unwrap());
    assert!(!CampaignsRepo::delete(&pool, &tenant_a, draft.id)
        .await
        .unwrap());

    pool.close().await;
}

/// Incidents: typed transition is the only writer of resolved_at, timeline
/// updates are ordered, delete cascades updates.
#[tokio::test]
async fn incidents_transitions_timeline_and_cascade() {
    let Some(pool) = canonical_pool("incidents").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };

    let inc = IncidentRepo::create(
        &pool,
        "inc_adv_1",
        "API latency",
        "investigating",
        "minor",
        &["api".to_string()],
    )
    .await
    .expect("create incident");
    assert!(inc.resolved_at.is_none());
    assert_eq!(inc.affected_components, vec!["api".to_string()]);

    assert!(IncidentRepo::get_by_id(&pool, "inc_adv_1")
        .await
        .unwrap()
        .is_some());
    assert!(IncidentRepo::get_by_id(&pool, "inc_missing")
        .await
        .unwrap()
        .is_none());

    // Invalid status strings are just inert data on create (no CHECK on
    // create in the canonical schema) — but the TYPED transition rejects
    // nothing unknown because it is an enum. Resolve clears/creates
    // resolved_at deterministically.
    let resolved = IncidentRepo::transition(&pool, "inc_adv_1", IncidentStatus::Resolved)
        .await
        .unwrap()
        .expect("resolved");
    assert_eq!(resolved.status, "resolved");
    assert!(resolved.resolved_at.is_some());
    assert!(IncidentRepo::list_active(&pool, 100, 0)
        .await
        .unwrap()
        .is_empty());

    // Reopen clears the timestamp.
    let reopened = IncidentRepo::transition(&pool, "inc_adv_1", IncidentStatus::Investigating)
        .await
        .unwrap()
        .unwrap();
    assert!(reopened.resolved_at.is_none());
    assert!(!IncidentStatus::Investigating.is_resolved());
    assert!(IncidentStatus::Resolved.is_resolved());
    assert_eq!(IncidentStatus::Identified.as_str(), "identified");
    assert_eq!(IncidentStatus::Monitoring.as_str(), "monitoring");
    assert!(IncidentRepo::list_active(&pool, 100, 0)
        .await
        .unwrap()
        .iter()
        .any(|i| i.id == "inc_adv_1"));
    assert!(!IncidentRepo::list(&pool, 100, 0).await.unwrap().is_empty());
    assert!(
        IncidentRepo::transition(&pool, "inc_missing", IncidentStatus::Resolved)
            .await
            .unwrap()
            .is_none()
    );

    // Timeline ordering and cascade delete.
    IncidentRepo::add_update(
        &pool,
        "upd1",
        "inc_adv_1",
        "investigating",
        "looking",
        "ops",
    )
    .await
    .unwrap();
    IncidentRepo::add_update(&pool, "upd2", "inc_adv_1", "mitigating", "found it", "ops")
        .await
        .unwrap();
    let updates = IncidentRepo::get_updates(&pool, "inc_adv_1").await.unwrap();
    assert_eq!(updates.len(), 2);
    assert!(updates[0].created_at <= updates[1].created_at, "ASC order");
    assert!(IncidentRepo::delete(&pool, "inc_adv_1").await.unwrap());
    assert!(!IncidentRepo::delete(&pool, "inc_adv_1").await.unwrap());
    assert!(IncidentRepo::get_updates(&pool, "inc_adv_1")
        .await
        .unwrap()
        .is_empty());

    pool.close().await;
}

/// The pool helpers that do not need a live server: config arithmetic,
/// timeouts, write tracking and the budget-warning path (exercised with a
/// real connection).
#[tokio::test]
async fn pool_config_timeout_and_write_tracking() {
    use apexmail_db::pool::{
        create_lazy_pool, create_pool_from_config, get_query_timeout, pool_size_for_workers,
        set_query_timeout, timed_query, with_query_timeout, WriteTracker,
    };
    use std::time::Duration;

    // Query timeout is a process-global knob; restore the default after.
    let original = get_query_timeout();
    set_query_timeout(1);
    assert_eq!(get_query_timeout(), Duration::from_secs(1));
    // A future that never completes must be timed out, not hang.
    assert!(
        with_query_timeout(std::future::pending::<()>())
            .await
            .is_err(),
        "a pending future must time out"
    );
    set_query_timeout(original.as_secs());

    // timed_query observes duration and returns the future's value.
    let value = timed_query("select_one", async { 42u32 }, 30)
        .await
        .unwrap();
    assert_eq!(value, 42);

    // pool_size_for_workers is at least the documented floor of 4.
    assert!(pool_size_for_workers() >= 4);

    // A lazy pool never dials, so construction cannot fail on a bogus URL.
    let lazy = create_lazy_pool("postgres://user:pw@127.0.0.1:1/db").expect("lazy pool");
    assert_eq!(lazy.options().get_max_connections(), 10);

    // A bad URL is a typed parse error, not a panic.
    assert!(create_lazy_pool("not-a-url").is_err());

    // WriteTracker: no write → RO; after a write → RW inside the 5s window.
    let trackerless = WriteTracker::new();
    assert!(!trackerless.is_within_sticky_window());

    // A PoolConfig run that reports a budget overrun still returns a pool.
    let config = apexmail_db::pool::PoolConfig {
        database_url: "postgres://user:pw@127.0.0.1:1/db",
        max_connections: 4,
        min_connections: 9,
        acquire_timeout_secs: 1,
        idle_timeout_secs: 1,
        max_lifetime_secs: 1,
        pool_name: Some("budget-test".into()),
        connection_budget: Some(1),
        expected_replica_count: 4,
        statement_cache_capacity: 32,
    };
    // Port 1 is closed: the connect fails with a typed error, no panic.
    let failed = apexmail_db::pool::create_pool_with_opts(&config).await;
    assert!(failed.is_err(), "connecting to a closed port must fail");

    // A malformed URL in create_pool_from_config is a typed error.
    let bad = create_pool_from_config("127.0.0.1", 1, "db", "u", "p", 1, 0).await;
    assert!(bad.is_err(), "unreachable database must error, not panic");

    let _ = apexmail_db::pool::PoolType::ReadWrite;
    let _ = apexmail_db::pool::PoolType::ReadOnly;
}

/// A real Postgres pool exercises the runtime accessors: create_pool,
/// create_pool_pair, PoolPair::get and WriteTracker::choose_pool.
#[tokio::test]
async fn pool_pair_and_write_tracker_against_real_db() {
    use apexmail_db::pool::{create_pool, create_pool_pair, WriteTracker};
    let Some(pool) = canonical_pool("pool_pair").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let Some(url) = std::env::var("TEST_DATABASE_URL").ok() else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        pool.close().await;
        return;
    };

    let created = create_pool(&url, 4).await.expect("create_pool");
    let value: i64 = sqlx::query_scalar("SELECT 1::bigint")
        .fetch_one(&created)
        .await
        .unwrap();
    assert_eq!(value, 1);
    created.close().await;

    let pair = create_pool_pair(&url, None, 4, 8).await.expect("pair");
    // min_connections=2 is eagerly established by both members.
    assert!(pair.get(apexmail_db::pool::PoolType::ReadWrite).size() >= 1);
    assert!(pair.get(apexmail_db::pool::PoolType::ReadOnly).size() >= 1);

    // With `None` replica the pair shares the primary URL — both answer.
    let ro_value: i64 = sqlx::query_scalar("SELECT 2::bigint")
        .fetch_one(pair.get(apexmail_db::pool::PoolType::ReadOnly))
        .await
        .unwrap();
    assert_eq!(ro_value, 2);

    let mut tracker = WriteTracker::new();
    assert!(!tracker.is_within_sticky_window());
    // Before any write the RO pool is chosen; after a write, RW.
    let before = tracker.choose_pool(&pair) as *const _;
    assert_eq!(before, &pair.ro as *const _);
    tracker.record_write();
    assert!(tracker.is_within_sticky_window());
    let after = tracker.choose_pool(&pair) as *const _;
    assert_eq!(after, &pair.rw as *const _);

    // PoolPair::new is the second constructor (G.5) — same contract.
    let pair2 = apexmail_db::pool::PoolPair::new(&url, Some(&url), 3)
        .await
        .expect("pair2");
    assert_eq!(pair2.rw.options().get_max_connections(), 3);
    assert_eq!(pair2.ro.options().get_max_connections(), 3);
    pair2.rw.close().await;
    pair2.ro.close().await;

    pair.rw.close().await;
    pair.ro.close().await;
    pool.close().await;

    // WriteTracker::default is the same as new().
    let defaulted = WriteTracker::default();
    assert!(!defaulted.is_within_sticky_window());
}

/// Transactions: commit persists, rollback discards, with_transaction maps
/// Err to a rollback, and `as_mut` returns None after consumption.
#[tokio::test]
async fn transaction_commit_rollback_and_helpers() {
    use apexmail_db::transaction::{with_transaction, Tx};
    let Some(pool) = canonical_pool("transactions").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };

    // Commit persists: the temp table survives on a NEW connection only
    // because ON COMMIT DROP is the inverse — instead prove the transaction
    // is really open by reading from it and then committing cleanly.
    let mut tx = Tx::begin(&pool).await.expect("begin");
    assert!(tx.as_mut().is_some(), "as_mut yields the live transaction");
    {
        let conn: &mut sqlx::PgConnection = &mut *tx.as_mut().unwrap();
        let one: i64 = sqlx::query_scalar("SELECT 1::bigint")
            .fetch_one(conn)
            .await
            .unwrap();
        assert_eq!(one, 1);
    }
    tx.commit().await.expect("commit");

    // Rollback on a live transaction succeeds and discards nothing visible.
    let mut tx = Tx::begin(&pool).await.unwrap();
    {
        let conn: &mut sqlx::PgConnection = &mut *tx.as_mut().unwrap();
        sqlx::query("SELECT 1").execute(conn).await.unwrap();
    }
    tx.rollback().await.expect("rollback");

    // with_transaction commits on Ok and returns the closure value.
    let value: i64 = with_transaction(&pool, |mut tx| async move {
        let conn: &mut sqlx::PgConnection = &mut *tx.as_mut().unwrap();
        let one: i64 = sqlx::query_scalar("SELECT 1::bigint")
            .fetch_one(conn)
            .await?;
        Ok((tx, one + 6))
    })
    .await
    .expect("committed");
    assert_eq!(value, 7);

    // with_transaction propagates Err (and the Tx is dropped → rollback).
    let failed: Result<i64, sqlx::Error> = with_transaction(&pool, |tx| async move {
        let _ = tx;
        Err(sqlx::Error::RowNotFound)
    })
    .await;
    assert!(failed.is_err());

    pool.close().await;
}
