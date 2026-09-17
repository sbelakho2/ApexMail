//! Adversarial tests for the inbox-placement HTTP handlers
//! (`src/routes.rs`): the VARCHAR(26) tenant-key validator, honest status
//! mapping (Protocol → 400, infrastructure → 500 without leaking
//! internals), pagination clamping, and the trends/provider plumbing.

use super::*;
use std::sync::Arc;

use crate::config::PlacementConfig;
use crate::engine::PlacementEngine;
use axum::http::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn dead_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(50))
        .connect_lazy("postgresql://offline@127.0.0.1:1/offline")
        .expect("lazy pool")
}

fn state(db: PgPool) -> Arc<PlacementState> {
    Arc::new(PlacementState {
        engine: Arc::new(PlacementEngine::new(PlacementConfig::default(), db.clone())),
        db,
    })
}

fn tenant_key(label: &str) -> String {
    let hex = Uuid::new_v4().simple().to_string();
    format!("{label}{}", &hex[..26 - label.len()])
}

async fn seed_tenant(db: &PgPool, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $1, $1, 'free', 'active')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .execute(db)
    .await
    .expect("seed tenant");
}

// ── validate_tenant_id ──────────────────────────────────────────────────────

#[test]
fn tenant_key_validator_enforces_varchar26_alphabet() {
    // Canonical shape accepted.
    assert!(validate_tenant_id("tenant-01_x").is_ok());
    assert!(validate_tenant_id(&"a".repeat(26)).is_ok(), "26 chars fit");

    // Empty and oversized refused.
    assert!(validate_tenant_id("").is_err());
    assert!(validate_tenant_id(&"a".repeat(27)).is_err());

    // Hostile alphabets refused (SQL/URL smuggles, unicode, whitespace).
    for bad in [
        "tenant id",
        "tenant/id",
        "tenant;drop",
        "tenant'quote",
        "tenant=eq",
        "tenant_idé",
        "日本語",
        "tenant%20id",
        "tenant+plus",
        "tenant.dot",
    ] {
        assert!(validate_tenant_id(bad).is_err(), "{bad:?} must be refused");
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_handler_maps_refusals_and_success() {
    let Some(db) = canonical_pool("ipx_routes_create").await else {
        return;
    };
    let tenant = tenant_key("c");
    seed_tenant(&db, &tenant).await;
    sqlx::query(
        "INSERT INTO domains (tenant_id, name, verified) VALUES ($1, 'send.example', true)",
    )
    .bind(&tenant)
    .execute(&db)
    .await
    .expect("seed domain");
    sqlx::query(
        "INSERT INTO seed_accounts (provider_id, email, imap_password_encrypted, is_active) \
         SELECT p.id, $1, 'pw', true FROM seed_providers p WHERE p.name = 'gmail'",
    )
    .bind(format!("{tenant}@seed.example"))
    .execute(&db)
    .await
    .expect("seed account");

    let st = state(db.clone());

    // Success → 201 CREATED with the serialized test.
    let (status, body) = create_placement_test(
        st.clone(),
        tenant.clone(),
        CreateTestRequest {
            name: Some("r".into()),
            from_email: "sender@send.example".into(),
            subject: "s".into(),
            body_text: None,
            body_html: None,
            target_providers: Some(vec!["gmail".into()]),
            schedule_at: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body.0["status"], "pending");

    // Protocol refusal (unverified From domain) → 400 with guidance.
    let (status, body) = create_placement_test(
        st.clone(),
        tenant.clone(),
        CreateTestRequest {
            name: None,
            from_email: "sender@unverified.example".into(),
            subject: "s".into(),
            body_text: None,
            body_html: None,
            target_providers: None,
            schedule_at: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.0["error"]
        .as_str()
        .unwrap_or_default()
        .contains("not a verified sending domain"));

    // Invalid tenant key → 400 before any query runs.
    let (status, _) = create_placement_test(
        st.clone(),
        "not a tenant key!!".into(),
        CreateTestRequest {
            name: None,
            from_email: "sender@send.example".into(),
            subject: "s".into(),
            body_text: None,
            body_html: None,
            target_providers: None,
            schedule_at: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Infrastructure failure (dead DB) → 500 with a NON-leaking message.
    let broken = state(dead_pool());
    let (status, body) = create_placement_test(
        broken,
        tenant,
        CreateTestRequest {
            name: None,
            from_email: "sender@send.example".into(),
            subject: "s".into(),
            body_text: None,
            body_html: None,
            target_providers: None,
            schedule_at: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body.0["error"], "failed to create placement test");
}

#[tokio::test]
async fn list_handler_paginates_and_filters() {
    let Some(db) = canonical_pool("ipx_routes_list").await else {
        return;
    };
    let tenant = tenant_key("l");
    seed_tenant(&db, &tenant).await;
    for i in 0..3 {
        sqlx::query(
            "INSERT INTO placement_tests \
             (id, tenant_id, name, status, from_email, subject, total_accounts, \
              completed_accounts, seed_accounts_used, created_at) \
             VALUES ($1, $2, NULL, $3, 's@send.example', 's', 0, 0, '{}', NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant)
        .bind(if i == 0 { "completed" } else { "pending" })
        .execute(&db)
        .await
        .expect("insert test");
    }

    let st = state(db.clone());

    // Unfiltered: total 3, default pagination.
    let (status, body) = list_placement_tests(st.clone(), tenant.clone(), None, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.0["total"], 3);
    assert_eq!(body.0["page"], 1);
    assert_eq!(body.0["per_page"], 20);

    // Status filter.
    let (status, body) = list_placement_tests(
        st.clone(),
        tenant.clone(),
        None,
        None,
        Some("completed".into()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.0["total"], 1);

    // Pagination params are clamped and honoured (page 2, per_page 2).
    let (status, body) =
        list_placement_tests(st.clone(), tenant.clone(), Some(2), Some(2), None).await;
    assert_eq!(status, StatusCode::OK);
    let items = body.0["tests"].as_array().expect("tests array");
    assert!(
        items.len() <= 1,
        "page 2 of 3 rows at per_page 2: {}",
        items.len()
    );

    // Invalid tenant → 400.
    let (status, _) = list_placement_tests(st.clone(), "BAD/KEY".into(), None, None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Dead DB → 500 with a generic message (both count and rows paths).
    let broken = state(dead_pool());
    let (status, body) = list_placement_tests(broken, tenant, None, None, None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body.0["error"], "database error");
}

#[tokio::test]
async fn get_handler_scopes_reports_and_reports_missing() {
    let Some(db) = canonical_pool("ipx_routes_get").await else {
        return;
    };
    let tenant = tenant_key("g");
    let outsider = tenant_key("o");
    seed_tenant(&db, &tenant).await;
    let test_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO placement_tests \
         (id, tenant_id, name, status, from_email, subject, total_accounts, \
          completed_accounts, seed_accounts_used, created_at) \
         VALUES ($1, $2, NULL, 'completed', 's@send.example', 's', 2, 2, '{}', NOW())",
    )
    .bind(test_id)
    .bind(&tenant)
    .execute(&db)
    .await
    .expect("insert test");
    let acct: (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email, imap_password_encrypted, is_active) \
         SELECT p.id, $1, 'pw', true FROM seed_providers p WHERE p.name = 'gmail' RETURNING id",
    )
    .bind(format!("{tenant}@seed.example"))
    .fetch_one(&db)
    .await
    .expect("seed account");
    sqlx::query(
        "INSERT INTO placement_results \
         (test_id, seed_account_id, inbox_type, delivery_time_ms, checked_at) \
         VALUES ($1, $2, 'inbox', 900, NOW())",
    )
    .bind(test_id)
    .bind(acct.0)
    .execute(&db)
    .await
    .expect("insert result");

    let st = state(db.clone());

    // Owner sees results + summary + score.
    let (status, body) = get_placement_test(st.clone(), tenant.clone(), test_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.0["id"], test_id.to_string());
    assert!(body.0["summary"].is_object(), "{}", body.0);
    assert_eq!(body.0["summary"]["inbox_pct"], 100.0);
    assert!(body.0["score"].is_object());

    // Another tenant's key → 404 (never the data).
    let (status, _) = get_placement_test(st.clone(), outsider, test_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Unknown id → 404.
    let (status, _) = get_placement_test(st.clone(), tenant.clone(), Uuid::new_v4()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Invalid tenant → 400.
    let (status, _) = get_placement_test(st, "../../etc".into(), test_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn trends_handler_clamps_windows_and_maps_errors() {
    let Some(db) = canonical_pool("ipx_routes_trends").await else {
        return;
    };
    let tenant = tenant_key("t");
    seed_tenant(&db, &tenant).await;
    let st = state(db.clone());

    // Empty window → ok with an empty list.
    let (status, body) = get_placement_trends(st.clone(), tenant.clone(), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.0["trends"].as_array().unwrap().len(), 0);

    // Provider filter parses (unknown → Other) and still answers.
    let (status, _) = get_placement_trends(
        st.clone(),
        tenant.clone(),
        Some(400), // clamped to 365
        Some("gmail".into()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Invalid tenant → 400; dead DB → 500.
    let (status, _) = get_placement_trends(st.clone(), "no/slash".into(), None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let broken = state(dead_pool());
    let (status, body) = get_placement_trends(broken, tenant, None, None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body.0["error"], "failed to get trends");
}

#[tokio::test]
async fn providers_handler_lists_and_degrades_honestly() {
    let Some(db) = canonical_pool("ipx_routes_providers").await else {
        return;
    };
    let st = state(db.clone());
    let (status, body) = list_seed_providers(st.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let providers = body.0["providers"].as_array().expect("providers");
    assert!(
        providers.iter().any(|p| p["name"] == "gmail"),
        "{providers:?}"
    );

    let broken = state(dead_pool());
    let (status, body) = list_seed_providers(broken).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body.0["error"], "failed to list providers");
}
