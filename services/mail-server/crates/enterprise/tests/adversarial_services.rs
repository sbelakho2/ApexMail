//! Adversarial coverage for the enterprise service surfaces not exercised by
//! the support suite: log streaming (secrets at rest, delivery accounting),
//! white-label domains/templates, sub-account quotas and API keys, QBR
//! generation, compliance lifecycle, template approval and the remaining
//! route-layer refusals.
//!
//! Each DB-backed test provisions its own canonical database through
//! `migrator::test_support::fresh_canonical_pool`; unset `TEST_DATABASE_URL`
//! soft-skips, a configured provisioning failure panics.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use enterprise::compliance::ComplianceService;
use enterprise::config::{Config, VolumeAllocationMode};
use enterprise::contracts::{
    AmendmentInput, CancelContractInput, ContractService, CreateContractInput, PurchaseOrderInput,
    SignContractInput,
};
use enterprise::log_streaming::LogStreamingService;
use enterprise::qbr::QBRService;
use enterprise::routes::{router, AppState};
use enterprise::sub_accounts::SubAccountService;
use enterprise::template_approval::TemplateApprovalService;
use enterprise::whitelabel::WhiteLabelService;
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_PRIVATE_PEM: &str = include_str!("keys/test_rsa_private.pem");
const TEST_PUBLIC_PEM: &str = include_str!("keys/test_rsa_public.pem");

async fn pool_for(test: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test, &format!("entdeep_{test}")).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

macro_rules! db_test {
    ($name:ident, $pool:ident, $body:block) => {
        #[tokio::test]
        async fn $name() {
            let Some($pool) = pool_for(stringify!($name)).await else {
                return;
            };
            $body
        }
    };
}

fn t26() -> String {
    format!("t{}", &Uuid::new_v4().simple().to_string()[..25])
}

async fn seed_tenant(pool: &PgPool, id: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at) \
         VALUES ($1, $2, $1, 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW()) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("t {id}"))
    .execute(pool)
    .await
    .expect("seed tenant");
}

fn ok<T: serde::Serialize + std::fmt::Debug>(
    result: Result<enterprise::types::ApiResult<T>, String>,
) -> T {
    let api = result.unwrap_or_else(|e| panic!("service error: {e}"));
    assert!(api.success, "expected ok, got error: {:?}", api.error);
    api.data.expect("ok result carries data")
}

fn err<T: serde::Serialize + std::fmt::Debug>(
    result: Result<enterprise::types::ApiResult<T>, String>,
) -> (String, String) {
    let api = result.unwrap_or_else(|e| panic!("hard error: {e}"));
    assert!(!api.success, "expected refusal, got data");
    (api.error.unwrap_or_default(), api.code.unwrap_or_default())
}

// ── Log streaming ───────────────────────────────────────────────────────

db_test!(
    log_stream_secrets_encrypted_at_rest_and_masked_in_responses,
    pool,
    {
        let svc = LogStreamingService::with_secret_key(pool.clone(), "kek-for-tests-0123456789");
        let tenant = t26();
        seed_tenant(&pool, &tenant).await;

        let secret_config = serde_json::json!({
            "url": "https://splunk.example.com:8088",
            "token": "super-secret-hec-token-1234",
            "api_key": "ddog-key-9988",
            "plain": "not-a-secret"
        });
        let stream = ok(svc
            .create(
                tenant.clone(),
                "splunk stream",
                Some("desc"),
                "splunk",
                Some(secret_config),
                Some(vec!["auth".into()]),
                Some(100),
                Some(30),
                false,
            )
            .await);
        // Response masks every secret field but keeps the tail.
        let masked = stream.destination_config.as_ref().unwrap();
        assert_eq!(masked["token"], "****1234");
        assert_eq!(masked["api_key"], "****9988");
        assert_eq!(masked["plain"], "not-a-secret");
        assert_eq!(masked["url"], "https://splunk.example.com:8088");

        // At rest the secret is encrypted (purpose-bound, tenant-bound), never
        // the plaintext.
        let stored: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT destination_config FROM ent_log_streams WHERE id=$1")
                .bind(stream.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let stored = stored.unwrap();
        let stored_token = stored["token"].as_str().unwrap();
        assert!(
            enterprise::field_encryption::FieldEncryptor::is_encrypted(stored_token),
            "stored token must be ciphertext: {stored_token}"
        );
        assert!(!stored_token.contains("super-secret"));

        // Get/list also mask.
        let fetched = ok(svc.get(stream.id).await);
        assert_eq!(fetched.destination_config.unwrap()["token"], "****1234");
        let listed = ok(svc.list(tenant.clone()).await);
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].destination_config.as_ref().unwrap()["token"],
            "****1234"
        );

        // A different KEK cannot decrypt: the response still masks the ciphertext
        // instead of leaking it or failing the request.
        let other_key =
            LogStreamingService::with_secret_key(pool.clone(), "different-kek-9876543210");
        let fetched = ok(other_key.get(stream.id).await);
        let config = fetched.destination_config.unwrap();
        assert!(
            config["token"].as_str().unwrap().starts_with("****"),
            "undecryptable secrets are still masked: {config}"
        );
        assert!(!config["token"].as_str().unwrap().contains("super-secret"));
    }
);

db_test!(log_stream_update_owner_check_pause_resume_delete, pool, {
    let svc = LogStreamingService::with_secret_key(pool.clone(), "kek-for-tests-0123456789");
    let tenant = t26();
    seed_tenant(&pool, &tenant).await;

    // Updating a nonexistent stream WITH a config must not create one.
    let missing = Uuid::new_v4();
    let (_, code) = err(svc
        .update(
            missing,
            None,
            None,
            Some(serde_json::json!({"token": "x"})),
            None,
        )
        .await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.update(missing, Some("n"), None, None, None).await);
    assert_eq!(code, "NOT_FOUND");

    let stream = ok(svc
        .create(
            tenant.clone(),
            "webhook",
            None,
            "webhook",
            Some(serde_json::json!({"url": "https://hook.example.com/x", "secret": "shared-1234"})),
            None,
            None,
            None,
            true,
        )
        .await);
    // Update re-encrypts replacement secrets and masks them.
    let updated = ok(svc
        .update(
            stream.id,
            Some("renamed"),
            Some("new description"),
            Some(
                serde_json::json!({"url": "https://hook.example.com/y", "secret": "rotated-5678"}),
            ),
            Some(vec!["delivery".into()]),
        )
        .await);
    assert_eq!(updated.name, "renamed");
    assert_eq!(
        updated.destination_config.as_ref().unwrap()["secret"],
        "****5678"
    );
    let raw: String =
        sqlx::query_scalar("SELECT destination_config->>'secret' FROM ent_log_streams WHERE id=$1")
            .bind(stream.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(enterprise::field_encryption::FieldEncryptor::is_encrypted(
        &raw
    ));

    // Pause → resume round trip.
    assert_eq!(ok(svc.pause(stream.id).await).status, "paused");
    assert_eq!(ok(svc.resume(stream.id).await).status, "active");
    let (_, code) = err(svc.pause(missing).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.resume(missing).await);
    assert_eq!(code, "NOT_FOUND");

    // Delete exactly once.
    ok(svc.delete(stream.id).await);
    let (_, code) = err(svc.delete(stream.id).await);
    assert_eq!(code, "NOT_FOUND");
});

db_test!(log_stream_delivery_accounting_and_failure_parking, pool, {
    let svc = LogStreamingService::with_secret_key(pool.clone(), "kek-for-tests-0123456789");
    let tenant = t26();
    seed_tenant(&pool, &tenant).await;
    let stream = ok(svc
        .create(
            tenant.clone(),
            "deliver",
            None,
            "webhook",
            None,
            None,
            None,
            None,
            false,
        )
        .await);

    // Success accounting increments totals.
    svc.record_delivery(stream.id, "b1", 10, 1_000, 5, true, None)
        .await
        .unwrap();
    svc.record_delivery(stream.id, "b2", 20, 2_000, 7, true, None)
        .await
        .unwrap();
    // Failure accounting sets last_error and counts.
    svc.record_delivery(stream.id, "b3", 0, 0, 3, false, Some("boom"))
        .await
        .unwrap();
    let (events, bytes, failures, last_error): (i64, i64, i32, Option<String>) = sqlx::query_as(
        "SELECT total_events_delivered, total_bytes_delivered, delivery_failures_count, last_error \
         FROM ent_log_streams WHERE id=$1",
    )
    .bind(stream.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((events, bytes, failures), (30, 3000, 1));
    assert_eq!(last_error.as_deref(), Some("boom"));

    // Stats: 2 of 3 batches succeeded within 24h; failed batch counts as
    // delivery but contributes no events/bytes.
    let stats = ok(svc.get_stats(stream.id).await);
    assert_eq!(stats.total_deliveries, 3);
    assert_eq!(stats.total_events, 30);
    assert_eq!(stats.total_bytes, 3000);
    assert!(
        (stats.success_rate - 66.66666).abs() < 0.01,
        "{}",
        stats.success_rate
    );
    // Unknown stream → honest zero-state with 100% (no division by zero).
    let empty = ok(svc.get_stats(Uuid::new_v4()).await);
    assert_eq!(empty.total_deliveries, 0);
    assert_eq!(empty.success_rate, 100.0);

    // The 10th consecutive failure flips the stream to 'error' state.
    for i in 0..9 {
        svc.record_delivery(stream.id, &format!("f{i}"), 0, 0, 1, false, Some("again"))
            .await
            .unwrap();
    }
    let status: String = sqlx::query_scalar("SELECT status FROM ent_log_streams WHERE id=$1")
        .bind(stream.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "error", "10 failures must trip the error state");
    // Failed streams are no longer in the active set.
    let active = svc.get_active_streams().await.unwrap();
    assert!(active.iter().all(|s| s.id != stream.id));

    // A paused stream is not active either.
    let paused = ok(svc
        .create(
            tenant.clone(),
            "p",
            None,
            "webhook",
            None,
            None,
            None,
            None,
            false,
        )
        .await);
    ok(svc.pause(paused.id).await);
    let active = svc.get_active_streams().await.unwrap();
    assert!(active.iter().all(|s| s.id != paused.id));
});

db_test!(
    log_stream_delivery_cycle_parks_failures_without_losing_them,
    pool,
    {
        let svc = LogStreamingService::with_secret_key(pool.clone(), "kek-for-tests-0123456789");
        let tenant = t26();
        seed_tenant(&pool, &tenant).await;

        // 1. No destination config → unsupported/absent config failure recorded.
        let no_config = ok(svc
            .create(
                tenant.clone(),
                "noconf",
                None,
                "webhook",
                None,
                None,
                None,
                None,
                false,
            )
            .await);
        // 2. Unknown destination type → refused without network I/O.
        let unknown = ok(svc
            .create(
                tenant.clone(),
                "unknown",
                None,
                "carrier_pigeon",
                Some(serde_json::json!({"url": "https://example.com/x"})),
                None,
                None,
                None,
                false,
            )
            .await);
        // 3. Webhook URL the SSRF guard must refuse (plain HTTP, loopback) —
        //    deterministic, no real network.
        let blocked = ok(svc
            .create(
                tenant.clone(),
                "blocked",
                None,
                "webhook",
                Some(serde_json::json!({"url": "http://127.0.0.1:9/hook"})),
                None,
                None,
                None,
                false,
            )
            .await);

        let delivered = svc.run_delivery_cycle().await.unwrap();
        assert_eq!(
            delivered, 0,
            "every sink fails, nothing is reported delivered"
        );

        // Every failed stream is parked with a recorded failed batch (the event
        // is not lost: the batch row survives with its error).
        for id in [no_config.id, unknown.id, blocked.id] {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM ent_stream_batches WHERE stream_id=$1 AND success = false",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(count, 1, "stream {id} must have exactly one parked failure");
            let last_error: Option<String> =
                sqlx::query_scalar("SELECT last_error FROM ent_log_streams WHERE id=$1")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert!(last_error.is_some(), "stream {id} must surface its error");
        }
        let blocked_error: String =
            sqlx::query_scalar("SELECT last_error FROM ent_log_streams WHERE id=$1")
                .bind(blocked.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            blocked_error.contains("HTTPS") || blocked_error.contains("blocked"),
            "SSRF refusal must be the recorded error: {blocked_error}"
        );

        // A stream whose secrets were written with a DIFFERENT KEK cannot be
        // decrypted by this service: the cycle records the failure and moves on.
        let foreign = LogStreamingService::with_secret_key(pool.clone(), "foreign-kek-1122334455");
        let owned = ok(foreign
            .create(
                tenant.clone(),
                "foreign",
                None,
                "webhook",
                Some(serde_json::json!({"url": "https://hook.example.com/x", "secret": "abc"})),
                None,
                None,
                None,
                false,
            )
            .await);
        let delivered = svc.run_delivery_cycle().await.unwrap();
        assert_eq!(delivered, 0);
        let foreign_error: Option<String> =
            sqlx::query_scalar("SELECT last_error FROM ent_log_streams WHERE id=$1")
                .bind(owned.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            foreign_error
                .as_deref()
                .unwrap_or_default()
                .contains("Decrypt"),
            "decrypt failure must be surfaced: {foreign_error:?}"
        );
    }
);

db_test!(log_stream_verify_refusals_are_typed_not_verified, pool, {
    let svc = LogStreamingService::with_secret_key(pool.clone(), "kek-for-tests-0123456789");
    let tenant = t26();
    seed_tenant(&pool, &tenant).await;

    let (_, code) = err(svc.verify(Uuid::new_v4()).await);
    assert_eq!(code, "NOT_FOUND");

    // Webhook without a URL: refused before any network call.
    let no_url = ok(svc
        .create(
            tenant.clone(),
            "nourl",
            None,
            "webhook",
            Some(serde_json::json!({})),
            None,
            None,
            None,
            false,
        )
        .await);
    let (msg, code) = err(svc.verify(no_url.id).await);
    assert_eq!(code, "VERIFICATION_FAILED");
    assert!(msg.contains("No webhook URL"), "{msg}");

    // Splunk missing HEC token: refused before any network call.
    let splunk = ok(svc
        .create(
            tenant.clone(),
            "splunk",
            None,
            "splunk",
            Some(serde_json::json!({"url": "https://splunk.example.com:8088"})),
            None,
            None,
            None,
            false,
        )
        .await);
    let (msg, code) = err(svc.verify(splunk.id).await);
    assert_eq!(code, "VERIFICATION_FAILED");
    assert!(msg.contains("HEC token"), "{msg}");

    // Datadog missing API key: refused before any network call.
    let datadog = ok(svc
        .create(
            tenant.clone(),
            "dd",
            None,
            "datadog",
            Some(serde_json::json!({})),
            None,
            None,
            None,
            false,
        )
        .await);
    let (msg, code) = err(svc.verify(datadog.id).await);
    assert_eq!(code, "VERIFICATION_FAILED");
    assert!(msg.contains("Datadog API key"), "{msg}");

    // Configured with a foreign KEK → typed decrypt refusal, never a
    // half-verified success.
    let foreign = LogStreamingService::with_secret_key(pool.clone(), "foreign-kek-1122334455");
    let owned = ok(foreign
        .create(
            tenant.clone(),
            "foreign",
            None,
            "splunk",
            Some(serde_json::json!({"url": "https://splunk.example.com:8088", "token": "t"})),
            None,
            None,
            None,
            false,
        )
        .await);
    let (_, code) = err(svc.verify(owned.id).await);
    assert_eq!(code, "SECRET_DECRYPT_FAILED");
});

// ── White-label ─────────────────────────────────────────────────────────

db_test!(
    whitelabel_config_css_sanitized_and_domain_verification_exact,
    pool,
    {
        let svc = WhiteLabelService::new(pool.clone());
        let tenant = t26();
        other_tenant(&pool, &tenant).await;

        // Not configured yet.
        let (_, code) = err(svc.get_config(tenant.clone()).await);
        assert_eq!(code, "NOT_FOUND");

        // Upsert sanitizes hostile CSS before persisting.
        let cfg = ok(svc
            .update_config(
                tenant.clone(),
                Some("Acme"),
                Some("https://cdn.example.com/logo.png"),
                None,
                Some("#000000"),
                None,
                Some("body { color: red; } <script>alert(1)</script> @import url(evil);"),
                Some("© Acme"),
                Some("support@acme.example"),
                Some("https://acme.example"),
            )
            .await);
        let css = cfg.custom_css.as_deref().unwrap_or_default();
        assert!(!css.contains("<script"), "script tags stripped: {css}");
        assert!(!css.contains("@import"), "@import stripped: {css}");
        assert!(css.contains("color"), "safe declarations kept: {css}");
        // Partial update keeps previous values (COALESCE semantics).
        let cfg2 = ok(svc
            .update_config(
                tenant.clone(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await);
        assert_eq!(cfg2.company_name.as_deref(), Some("Acme"));
        assert!(cfg2.custom_css.is_some());

        // Domain lifecycle: add issues a random token and TXT record.
        let domain = ok(svc
            .add_domain(tenant.clone(), "mail.acme.example", "tracking")
            .await);
        assert_eq!(domain.verification_status, "pending");
        assert!(!domain
            .verification_token
            .clone()
            .unwrap_or_default()
            .is_empty());
        let records = domain.dns_records.clone().unwrap();
        assert_eq!(records.as_array().unwrap().len(), 2, "CNAME + TXT");
        assert!(records
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["record_type"] == "TXT"
                && r["value"]
                    .as_str()
                    .unwrap()
                    .contains("apexmail-verification=")));

        // Verification with a lookup that does NOT contain the token fails.
        let token = domain.verification_token.clone().unwrap();
        let failed = ok(svc
            .verify_domain_with_lookup(domain.id, |_host| async {
                Ok(vec!["some-other-txt-record".to_string()])
            })
            .await);
        assert_eq!(failed.verification_status, "failed");
        assert!(
            failed.verified_at.is_none(),
            "failed verification stamps nothing"
        );

        // A DNS lookup ERROR is a failure, never a silent verify.
        let errored = ok(svc
            .verify_domain_with_lookup(domain.id, |_host| async { Err("DNS timeout".to_string()) })
            .await);
        assert_eq!(errored.verification_status, "failed");

        // The exact token (even embedded in a longer TXT string) verifies once.
        let verified = ok(svc
            .verify_domain_with_lookup(domain.id, move |_host| async move {
                Ok(vec![format!("apexmail-verification={token}")])
            })
            .await);
        assert_eq!(verified.verification_status, "verified");
        assert!(verified.verified_at.is_some());

        // Unknown domain id.
        let (_, code) = err(svc
            .verify_domain_with_lookup(Uuid::new_v4(), |_h| async { Ok(vec![]) })
            .await);
        assert_eq!(code, "NOT_FOUND");

        // Legacy row without a token gets one issued, and only the TXT record
        // then verifies it.
        let legacy = ok(svc
            .add_domain(tenant.clone(), "legacy.acme.example", "landing_page")
            .await);
        sqlx::query("UPDATE ent_whitelabel_domains SET verification_token = NULL WHERE id=$1")
            .bind(legacy.id)
            .execute(&pool)
            .await
            .unwrap();
        let reissued = ok(svc
            .verify_domain_with_lookup(legacy.id, |_h| async { Ok(vec![]) })
            .await);
        assert_eq!(reissued.verification_status, "failed");
        let new_token: Option<String> =
            sqlx::query_scalar("SELECT verification_token FROM ent_whitelabel_domains WHERE id=$1")
                .bind(legacy.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(new_token.is_some(), "legacy row received a fresh token");

        // Listing + ownership-scoped delete.
        let list = ok(svc.list_domains(tenant.clone(), 10, 0).await);
        assert_eq!(list.len(), 2);
        let (_, code) = err(svc.remove_domain(domain.id, t26()).await);
        assert_eq!(code, "NOT_FOUND", "cross-tenant delete refused");
        ok(svc.remove_domain(domain.id, tenant.clone()).await);
        let list = ok(svc.list_domains(tenant.clone(), 10, 0).await);
        assert_eq!(list.len(), 1);

        // Email templates: upsert then partial update must not wipe values.
        let tpl = ok(svc
            .update_email_templates(
                tenant.clone(),
                "welcome",
                Some("Welcome to {{name}}"),
                Some("<h1>Hello</h1>"),
                None,
            )
            .await);
        assert_eq!(tpl.template_type, "welcome");
        let tpl2 = ok(svc
            .update_email_templates(tenant.clone(), "welcome", None, None, Some("plain text"))
            .await);
        assert_eq!(
            tpl2.subject_template.as_deref(),
            Some("Welcome to {{name}}")
        );
        assert_eq!(tpl2.text_template.as_deref(), Some("plain text"));
        let templates = ok(svc.get_email_templates(tenant.clone()).await);
        assert_eq!(templates.len(), 1);
        let none = ok(svc.get_email_templates(t26()).await);
        assert!(none.is_empty());
    }
);

async fn other_tenant(pool: &PgPool, id: &str) {
    seed_tenant(pool, id).await;
}

// ── Sub-accounts ────────────────────────────────────────────────────────

db_test!(sub_accounts_quota_and_api_key_lifecycle, pool, {
    let svc = SubAccountService::new(pool.clone(), 2, VolumeAllocationMode::Fixed);
    let parent = t26();
    seed_tenant(&pool, &parent).await;

    let a = ok(svc
        .create(
            parent.clone(),
            "sub-a",
            Some("a@x.example"),
            None,
            None,
            Some(100),
            true,
        )
        .await);
    let b = ok(svc
        .create(parent.clone(), "sub-b", None, None, None, None, false)
        .await);
    // Third create hits the per-parent quota exactly, with a clean code.
    let (msg, code) = err(svc
        .create(parent.clone(), "sub-c", None, None, None, None, true)
        .await);
    assert_eq!(code, "QUOTA_EXCEEDED");
    assert!(msg.contains("(2)"), "{msg}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ent_sub_accounts WHERE parent_id=$1")
        .bind(&parent)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2, "refused create must not persist");

    // Get/list and filters.
    assert_eq!(ok(svc.get(a.id).await).name, "sub-a");
    let (_, code) = err(svc.get(Uuid::new_v4()).await);
    assert_eq!(code, "NOT_FOUND");
    assert_eq!(ok(svc.list(parent.clone(), None, 10, 0).await).len(), 2);
    // Suspended entries drop out of the active filter.
    ok(svc.suspend(a.id, Some("abuse")).await);
    let active = ok(svc.list(parent.clone(), Some("active"), 10, 0).await);
    assert_eq!(active.len(), 1);
    let suspended = ok(svc.list(parent.clone(), Some("suspended"), 10, 0).await);
    assert_eq!(suspended.len(), 1);

    // Update + not-found paths.
    let updated = ok(svc
        .update(
            b.id,
            Some("renamed"),
            Some("b2@x.example"),
            Some(500),
            Some(serde_json::json!({"k": 1})),
        )
        .await);
    assert_eq!(updated.name, "renamed");
    assert_eq!(updated.volume_limit, Some(500));
    let (_, code) = err(svc
        .update(Uuid::new_v4(), Some("x"), None, None, None)
        .await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.suspend(Uuid::new_v4(), None).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.delete(Uuid::new_v4()).await);
    assert_eq!(code, "NOT_FOUND");

    // Stats aggregate exactly.
    let stats = ok(svc.get_stats(parent.clone()).await);
    assert_eq!(stats.total, 2);
    assert_eq!(stats.active, 1);
    assert_eq!(stats.total_volume_used, 0);
    assert_eq!(stats.total_volume_limit, 600);

    // API keys: raw key returned once, hashes stripped from listings,
    // verification honours revocation and expiry.
    let created = ok(svc
        .create_api_key(b.id, "ci", Some(vec!["send".into()]), Some(60))
        .await);
    let raw = created["key"].as_str().unwrap().to_string();
    let key_id = created["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    assert!(svc.verify_api_key(&raw).await.unwrap().is_some());
    assert!(
        svc.verify_api_key("not-a-key").await.unwrap().is_none(),
        "unknown raw keys never resolve"
    );
    let keys = ok(svc.list_api_keys(b.id).await);
    assert_eq!(keys.len(), 1);
    assert!(
        keys[0].key_hash.is_empty(),
        "key hash must never be returned"
    );
    // Revocation is immediate and idempotent.
    ok(svc.revoke_api_key(b.id, key_id).await);
    assert!(svc.verify_api_key(&raw).await.unwrap().is_none());
    ok(svc.revoke_api_key(b.id, key_id).await);
    // Revoking a foreign key id under this sub-account is refused.
    let (_, code) = err(svc.revoke_api_key(b.id, Uuid::new_v4()).await);
    assert_eq!(code, "NOT_FOUND");

    // Expired keys do not verify.
    let expired = ok(svc.create_api_key(b.id, "old", None, None).await);
    let expired_raw = expired["key"].as_str().unwrap().to_string();
    let expired_id = expired["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    sqlx::query(
        "UPDATE ent_sub_account_api_keys SET expires_at = NOW() - interval '1 second' WHERE id=$1",
    )
    .bind(expired_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(svc.verify_api_key(&expired_raw).await.unwrap().is_none());

    // Delete removes exactly one row.
    ok(svc.delete(b.id).await);
    let (_, code) = err(svc.delete(b.id).await);
    assert_eq!(code, "NOT_FOUND");
    assert_eq!(ok(svc.list(parent, None, 10, 0).await).len(), 1);
});

// ── QBR ─────────────────────────────────────────────────────────────────

db_test!(qbr_lifecycle_generation_and_goal_progress, pool, {
    let svc = QBRService::new(pool.clone());
    let tenant = t26();
    seed_tenant(&pool, &tenant).await;

    // Unknown ids.
    let (_, code) = err(svc.get(Uuid::new_v4()).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.generate(Uuid::new_v4()).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.mark_delivered(Uuid::new_v4()).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.submit_feedback(Uuid::new_v4(), 5, None).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.update_goal(Uuid::new_v4(), Uuid::new_v4(), 1.0).await);
    assert_eq!(code, "NOT_FOUND");

    // Schedule + list.
    let qbr = ok(svc
        .schedule(
            tenant.clone(),
            3,
            2026,
            chrono::NaiveDate::from_ymd_opt(2026, 9, 1),
            Some(serde_json::json!([{"name": "Alice"}])),
        )
        .await);
    assert_eq!(qbr.status, "scheduled");
    assert_eq!(ok(svc.list(tenant.clone(), 10, 0).await).len(), 1);
    assert_eq!(
        ok(svc.list(tenant.clone(), 10, 1).await).len(),
        0,
        "offset honoured"
    );

    // Seed rolling metrics inside Q3 and one row OUTSIDE it; generation must
    // only count the quarter's rows.
    sqlx::query(
        "INSERT INTO ent_sending_metrics (id, account_id, period_start, sent, delivered, bounced, opened, clicked) \
         VALUES (gen_random_uuid(), $1, '2026-08-01T00:00:00Z', 1000, 900, 100, 450, 90)",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO ent_sending_metrics (id, account_id, period_start, sent, delivered, bounced, opened, clicked) \
         VALUES (gen_random_uuid(), $1, '2026-12-01T00:00:00Z', 9999, 9999, 0, 0, 0)",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .unwrap();
    let generated = ok(svc.generate(qbr.id).await);
    assert_eq!(generated["metrics"]["sent"], 1000);
    assert_eq!(generated["metrics"]["delivered"], 900);
    assert_eq!(generated["metrics"]["bounced"], 100);
    let delivery_rate = generated["metrics"]["delivery_rate"].as_f64().unwrap();
    assert!((delivery_rate - 90.0).abs() < 1e-9, "{delivery_rate}");
    let bounce_rate = generated["metrics"]["bounce_rate"].as_f64().unwrap();
    assert!((bounce_rate - 10.0).abs() < 1e-9, "{bounce_rate}");
    let open_rate = generated["metrics"]["open_rate"].as_f64().unwrap();
    assert!((open_rate - 50.0).abs() < 1e-9, "{open_rate}");
    // An empty quarter divides nothing by zero.
    let empty = ok(svc.schedule(tenant.clone(), 1, 2026, None, None).await);
    let generated = ok(svc.generate(empty.id).await);
    assert_eq!(generated["metrics"]["sent"], 0);
    assert_eq!(generated["metrics"]["delivery_rate"], 0.0);

    // Delivered + feedback.
    let delivered = ok(svc.mark_delivered(qbr.id).await);
    assert_eq!(delivered.status, "delivered");
    assert!(delivered.delivered_date.is_some());
    let feedback = ok(svc.submit_feedback(qbr.id, 4, Some("solid")).await);
    assert_eq!(feedback.status, "feedback_received");
    assert_eq!(feedback.feedback.unwrap()["rating"], 4);

    // Goal progress: baseline→target mapping, including a degenerate range.
    let goal_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ent_qbr_goals (id, qbr_id, title, status, baseline_value, target_value, current_value) \
         VALUES ($1, $2, 'deliverability', 'in_progress', 90, 100, 90)",
    )
    .bind(goal_id)
    .bind(qbr.id)
    .execute(&pool)
    .await
    .unwrap();
    let goal = ok(svc.update_goal(qbr.id, goal_id, 95.0).await);
    assert!((goal.progress_percent.unwrap() - 50.0).abs() < 1e-9);
    assert_eq!(goal.status, "in_progress");
    let goal = ok(svc.update_goal(qbr.id, goal_id, 102.0).await);
    assert_eq!(goal.status, "completed");
    assert!(
        (goal.progress_percent.unwrap() - 120.0).abs() < 1e-9,
        "clamped at 200"
    );
    // Goal from another QBR is invisible.
    let other_qbr = ok(svc.schedule(tenant.clone(), 4, 2026, None, None).await);
    let (_, code) = err(svc.update_goal(other_qbr.id, goal_id, 50.0).await);
    assert_eq!(code, "NOT_FOUND");

    // Benchmarks: empty industry is an empty list, never an error.
    let industry = format!("industry-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let benchmarks = ok(svc.get_benchmarks(&industry).await);
    assert!(benchmarks.is_empty());
    sqlx::query(
        "INSERT INTO ent_industry_benchmarks (id, industry, metric_name, metric_value, percentile_25, percentile_50, percentile_75, percentile_90, unit) \
         VALUES (gen_random_uuid(), $1, 'delivery_rate', 97.0, 90, 95, 98, 99, 'percent')",
    )
    .bind(&industry)
    .execute(&pool)
    .await
    .unwrap();
    let benchmarks = ok(svc.get_benchmarks(&industry).await);
    assert_eq!(benchmarks.len(), 1);
    assert_eq!(benchmarks[0].metric_name, "delivery_rate");
});

db_test!(qbr_daily_rollup_is_idempotent_per_day, pool, {
    let svc = QBRService::new(pool.clone());
    let tenant = t26();
    seed_tenant(&pool, &tenant).await;

    for (event_type, count) in [("sent", 3), ("delivered", 2), ("bounced", 1)] {
        for _ in 0..count {
            sqlx::query(
                "INSERT INTO events (id, tenant_id, event_type, timestamp) \
                 VALUES ($1, $2, $3, '2026-05-10T12:00:00Z')",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&tenant)
            .bind(event_type)
            .execute(&pool)
            .await
            .unwrap();
        }
    }
    let day = chrono::NaiveDate::from_ymd_opt(2026, 5, 10).unwrap();
    let first = svc.rollup_daily_sending_metrics(day).await.unwrap();
    assert_eq!(first, 1, "one account-day row");
    let (sent, delivered, bounced): (i64, i64, i64) = sqlx::query_as(
        "SELECT sent, delivered, bounced FROM ent_sending_metrics WHERE account_id=$1",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((sent, delivered, bounced), (3, 2, 1));
    // Re-running replaces, never duplicates.
    let second = svc.rollup_daily_sending_metrics(day).await.unwrap();
    assert_eq!(second, 1);
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ent_sending_metrics WHERE account_id=$1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 1, "rollup is idempotent");
});

// ── Compliance ──────────────────────────────────────────────────────────

db_test!(
    compliance_lifecycle_not_configured_and_attestations,
    pool,
    {
        let svc = ComplianceService::new(pool.clone());
        let tenant = t26();
        seed_tenant(&pool, &tenant).await;

        // Unconfigured tenant: every mutation reports NOT_FOUND, reads report
        // configured:false — never a phantom success.
        let (_, code) = err(svc.get_config(tenant.clone()).await);
        assert_eq!(code, "NOT_FOUND");
        let (_, code) = err(svc.sign_baa(tenant.clone(), "N", "T", "n@x.example").await);
        assert_eq!(code, "NOT_FOUND");
        let (_, code) = err(svc.enable_zero_retention(tenant.clone()).await);
        assert_eq!(code, "NOT_FOUND");
        let (_, code) = err(svc.generate_report(tenant.clone()).await);
        assert_eq!(code, "NOT_FOUND");
        let status = ok(svc.get_status(tenant.clone()).await);
        assert_eq!(status["configured"], false);

        // Enabling SOC2 forces encryption at rest; enabling again keeps it.
        let cfg = ok(svc.enable(tenant.clone(), vec!["soc2".into()], false).await);
        assert!(cfg.encryption_at_rest, "SOC2 requires encryption at rest");
        assert!(cfg.encryption_in_transit);
        assert_eq!(cfg.audit_log_retention_days, 2555);
        // Re-enabling with an enforcing framework still keeps encryption at rest.
        let cfg = ok(svc.enable(tenant.clone(), vec!["gdpr".into()], false).await);
        assert!(cfg.encryption_at_rest, "GDPR requires encryption at rest");

        // BAA signature is durable.
        let cfg = ok(svc
            .sign_baa(tenant.clone(), "Dr A", "CTO", "a@x.example")
            .await);
        assert!(cfg.baa_signed);
        assert_eq!(cfg.baa_signatory_name.as_deref(), Some("Dr A"));
        // Re-enabling frameworks does not wipe the attestation.
        let cfg = ok(svc.enable(tenant.clone(), vec!["hipaa".into()], true).await);
        assert!(cfg.baa_signed, "attestations survive re-enable");
        assert!(cfg.baa_signed_at.is_some());

        // Zero retention.
        let cfg = ok(svc.enable_zero_retention(tenant.clone()).await);
        assert!(cfg.zero_retention_mode);

        // Audit logging + filtering, then report counting.
        svc.log_audit(
            tenant.clone(),
            Some("user-1"),
            "login",
            "session",
            None,
            None,
            Some(serde_json::json!({"ok": true})),
            Some("127.0.0.1"),
            Some("agent"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        svc.log_audit(
            tenant.clone(),
            None,
            "export",
            "report",
            Some("r1"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let logs = ok(svc
            .get_audit_logs(tenant.clone(), Some("login"), None, 50, 0)
            .await);
        assert_eq!(logs.len(), 1);
        let logs = ok(svc
            .get_audit_logs(tenant.clone(), None, Some("report"), 50, 0)
            .await);
        assert_eq!(logs.len(), 1);

        // Data access request lifecycle.
        let req = ok(svc
            .request_data_access(
                tenant.clone(),
                "user-1",
                "u@x.example",
                "export",
                Some("mailbox"),
                Some("subject request"),
                None,
            )
            .await);
        assert_eq!(req.status, "pending");
        assert_eq!(ok(svc.get_data_access_request(req.id).await).id, req.id);
        let (_, code) = err(svc.get_data_access_request(Uuid::new_v4()).await);
        assert_eq!(code, "NOT_FOUND");
        let approved = ok(svc.approve_data_access(req.id, "dpo", 60).await);
        assert_eq!(approved.status, "approved");
        assert!(approved.access_token.is_some());
        assert!(approved.expires_at.is_some());
        let (_, code) = err(svc.approve_data_access(Uuid::new_v4(), "dpo", 60).await);
        assert_eq!(code, "NOT_FOUND");

        // Deletion request + report.
        let del = ok(svc
            .request_data_deletion(tenant.clone(), "user-1", "u@x.example", None)
            .await);
        assert_eq!(del.status, "pending");
        let report = ok(svc.generate_report(tenant.clone()).await);
        assert_eq!(report["audit_log_entries"], 2);
        assert_eq!(report["data_access_requests"], 2);
        assert_eq!(report["baa_signed"], true);
        assert_eq!(report["zero_retention_mode"], true);
        let status = ok(svc.get_status(tenant.clone()).await);
        assert_eq!(status["configured"], true);
        assert_eq!(status["baa_signed"], true);
    }
);

// ── Template approval ───────────────────────────────────────────────────

db_test!(template_approval_spam_gate_review_and_stats, pool, {
    // Reject threshold 40: a spammy template is rejected automatically, never
    // silently approved.
    let svc = TemplateApprovalService::new(pool.clone(), 10, 40);
    let tenant = t26();
    seed_tenant(&pool, &tenant).await;

    let spammy = "<html><body>FREE winner!! click here now http://a http://b http://c http://d</body></html>";
    let submission = ok(svc
        .submit(
            tenant.clone(),
            "spam",
            "URGENT!! act now",
            spammy,
            None,
            "author",
        )
        .await);
    assert_eq!(
        submission.status, "rejected",
        "high spam score auto-rejects"
    );
    assert!(submission.spam_score.unwrap() >= 40.0);

    let clean = ok(
        svc.submit(
            tenant.clone(),
            "clean",
            "Monthly update",
            "<p>Hello, here is your update. <a href=\"https://x.example/unsubscribe\">Unsubscribe</a></p>",
            Some("plain"),
            "author",
        )
        .await,
    );
    assert_eq!(clean.status, "pending", "never auto-approved");

    // Get/list + filters + not found.
    assert_eq!(ok(svc.get_submission(clean.id).await).id, clean.id);
    let (_, code) = err(svc.get_submission(Uuid::new_v4()).await);
    assert_eq!(code, "NOT_FOUND");
    assert_eq!(
        ok(svc.list_submissions(tenant.clone(), None, 10, 0).await).len(),
        2
    );
    assert_eq!(
        ok(svc
            .list_submissions(tenant.clone(), Some("pending"), 10, 0)
            .await)
        .len(),
        1
    );

    // Review actions: each transitions the exact submission; unknown ids are
    // refusals, never no-op successes.
    let (_, code) = err(svc.approve(Uuid::new_v4(), "rev", None).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.reject(Uuid::new_v4(), "rev", "no").await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.request_changes(Uuid::new_v4(), "rev", "fix").await);
    assert_eq!(code, "NOT_FOUND");
    let approved = ok(svc.approve(clean.id, "rev", Some("lgtm")).await);
    assert_eq!(approved.status, "approved");
    assert_eq!(approved.reviewed_by.as_deref(), Some("rev"));
    // State transition is an update, not a state machine — a rejected
    // submission can be re-reviewed, but the audit trail keeps the reviewer.
    let rejected = ok(svc.reject(spammy_id(&submission), "rev2", "spam").await);
    assert_eq!(rejected.status, "rejected");
    assert_eq!(rejected.reviewed_by.as_deref(), Some("rev2"));
    let changes = ok(svc
        .request_changes(submission_id(&submission), "rev3", "shrink the CTA")
        .await);
    assert_eq!(changes.status, "changes_requested");

    // Stats count every bucket.
    let stats = ok(svc.get_stats(tenant.clone()).await);
    assert_eq!(stats["total"], 2);
    assert_eq!(stats["approved"], 1);
    assert_eq!(stats["changes_requested"], 1);
});

fn submission_id(submission: &enterprise::types::TemplateSubmission) -> Uuid {
    submission.id
}

fn spammy_id(submission: &enterprise::types::TemplateSubmission) -> Uuid {
    submission.id
}

// ── Contracts: refusal edges ────────────────────────────────────────────

db_test!(contracts_refusal_edges_never_phantom_succeed, pool, {
    let svc = ContractService::new(pool.clone());
    let tenant = t26();
    seed_tenant(&pool, &tenant).await;
    let missing = Uuid::new_v4();

    // Missing contracts: every read/action is honest NOT_FOUND.
    let (_, code) = err(svc.get_contract(missing, &tenant).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.get_contract_usage(&tenant, missing).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc
        .cancel_contract(
            &tenant,
            missing,
            CancelContractInput {
                reason: "x".into(),
                effective_date: None,
            },
        )
        .await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc.get_renewal_quote(&tenant, missing).await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc
        .submit_purchase_order(
            &tenant,
            missing,
            PurchaseOrderInput {
                po_number: "PO-1".into(),
                amount: 100,
                issued_date: chrono::Utc::now(),
                expiry_date: None,
                attachment_url: None,
            },
        )
        .await);
    assert_eq!(code, "NOT_FOUND");
    let (_, code) = err(svc
        .request_amendment(
            &tenant,
            missing,
            AmendmentInput {
                reason: "why".into(),
                proposed_changes: serde_json::json!({}),
            },
        )
        .await);
    assert_eq!(code, "NOT_FOUND");

    // Create a real contract to exercise state refusals.
    let start = chrono::Utc::now();
    let contract = ok(svc
        .create_contract(CreateContractInput {
            tenant_id: tenant.clone(),
            name: "Adversarial".into(),
            start_date: start,
            end_date: start + chrono::Duration::days(365),
            auto_renew: false,
            base_price: 12_000,
            committed_volume: 1_000_000,
            overage_rate: 5,
            annual_prepay_discount: 0,
            additional_fees: vec![],
            payment_terms_days: 30,
            sla_credit_percentage: 0,
            custom_terms: None,
            allow_purchase_orders: true,
            dedicated_support: false,
            custom_features: vec![],
            custom_sla: None,
        })
        .await);

    // Signing with a future timestamp is refused (no forward-dating).
    let (_, code) = err(svc
        .sign_contract(
            &tenant,
            contract.id,
            SignContractInput {
                signature_data: "sig".into(),
                signer_name: "Alice".into(),
                signer_title: "COO".into(),
                signed_at: chrono::Utc::now() + chrono::Duration::hours(2),
            },
        )
        .await);
    assert_eq!(code, "INVALID_SIGNATURE_TIME");

    // Counter-signing before the tenant signed is refused, transactionally.
    let (_, code) = err(svc.counter_sign_contract(contract.id).await);
    assert_eq!(code, "NO_TENANT_SIGNATURE");

    // Scheduled cancellation is explicitly unsupported.
    let (_, code) = err(svc
        .cancel_contract(
            &tenant,
            contract.id,
            CancelContractInput {
                reason: "later".into(),
                effective_date: Some(chrono::Utc::now() + chrono::Duration::days(30)),
            },
        )
        .await);
    assert_eq!(code, "SCHEDULED_CANCELLATION_UNSUPPORTED");

    // Usage of a real contract is a zeroed summary when nothing was recorded.
    let usage = ok(svc.get_contract_usage(&tenant, contract.id).await);
    assert_eq!(usage.current_usage, 0);
    assert!(
        usage.committed_volume > 0 && usage.committed_volume <= 1_000_000,
        "current period carries a prorated committed volume, got {}",
        usage.committed_volume
    );
    assert_eq!(usage.percent_used, 0.0);
    assert_eq!(usage.overage_estimate, 0);
});

// ── Routes: deployments / ips / sub-accounts / qbr / whitelabel ─────────

async fn build_router(pool: &PgPool, tenant: &str) -> (Router, String) {
    let mut config = Config::from_env().expect("Config::from_env");
    config.jwt_public_key_pem = TEST_PUBLIC_PEM.to_string();
    config.jwt_audience = None;
    config.jwt_issuer = None;
    config.metrics_token = None;
    config.log_stream.encryption_key = "adversarial-services-key".to_string();
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = router(Arc::new(AppState::new(
        pool.clone(),
        config,
        recorder.handle(),
    )));
    #[derive(serde::Serialize)]
    struct Claims<'a> {
        sub: &'a str,
        tenant_id: &'a str,
        admin: bool,
        exp: usize,
    }
    let claims = Claims {
        sub: "route-user",
        tenant_id: tenant,
        admin: true,
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .unwrap();
    (app, token)
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .expect("request body"),
        None => builder.body(Body::empty()).expect("empty request"),
    };
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

db_test!(routes_deployments_ips_and_log_streams_surface, pool, {
    let tenant = t26();
    seed_tenant(&pool, &tenant).await;
    let (app, token) = build_router(&pool, &tenant).await;

    // Deployment create → list → get → provision → health → provision again.
    let (status, json) = call(
        &app,
        "POST",
        "/deployments",
        Some(&token),
        Some(serde_json::json!({
            "tenant_id": tenant, "name": "prod", "deployment_type": "dedicated",
            "region": "eu-central-1", "config": {"size": "l"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let deploy_id = json["data"]["id"].as_str().unwrap().to_string();
    let (status, json) = call(
        &app,
        "GET",
        &format!("/deployments/tenant/{tenant}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"].as_array().unwrap().len(), 1);
    let (status, _) = call(
        &app,
        "GET",
        &format!("/deployments/{deploy_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, json) = call(
        &app,
        "GET",
        &format!("/deployments/{deploy_id}/health"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["health_status"], "unknown");

    // Create validation is a clean 400 now.
    let (status, json) = call(
        &app,
        "POST",
        "/deployments",
        Some(&token),
        Some(serde_json::json!({
            "tenant_id": tenant, "name": "x", "deployment_type": "bogus"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");

    // IP pool: allocate a seeded address, then reputation and listing.
    sqlx::query(
        "INSERT INTO ip_pool_available (id, ip_address, region, status, is_warmed, reputation_score) \
         VALUES (gen_random_uuid(), '203.0.113.77'::inet, 'eu-central-1', 'available', true, 88)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let (status, json) = call(
        &app,
        "POST",
        "/ips/allocate",
        Some(&token),
        Some(serde_json::json!({"tenant_id": tenant, "ip_address": "203.0.113.77"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let ip_id = json["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        json["data"]["ip_address"], "203.0.113.77",
        "no /32 suffix leaks"
    );
    let (status, json) = call(
        &app,
        "GET",
        "/ips/reputation/203.0.113.77",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    // Fresh allocation has no history: the score is derived (no penalty).
    assert_eq!(json["data"]["reputation_score"], 100.0);
    let (status, json) = call(
        &app,
        "GET",
        &format!("/ips/tenant/{tenant}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"].as_array().unwrap().len(), 1);
    let (status, _) = call(&app, "GET", &format!("/ips/{ip_id}"), Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    // Non-pool allocation is refused with a machine code and no write.
    let (status, json) = call(
        &app,
        "POST",
        "/ips/allocate",
        Some(&token),
        Some(serde_json::json!({"tenant_id": tenant, "ip_address": "198.51.100.9"})),
    )
    .await;
    assert_eq!(json["success"], false, "{status} {json}");
    assert_eq!(json["code"], "IP_NOT_IN_POOL");
    let dedicated: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ent_dedicated_ips WHERE ip_address = '198.51.100.9'::inet",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(dedicated, 0, "refused allocation must not write");

    // BYOIP register → verify with the returned token; replay refused.
    let (status, json) = call(
        &app,
        "POST",
        "/ips/byoip",
        Some(&token),
        Some(serde_json::json!({"tenant_id": tenant, "cidr_block": "192.0.2.0/24"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let range_id = json["data"]["id"].as_str().unwrap().to_string();
    let vtoken = json["data"]["verification_token"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, json) = call(
        &app,
        "POST",
        &format!("/ips/byoip/{range_id}/verify"),
        Some(&token),
        Some(serde_json::json!({"verification_token": "wrong"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{json}");
    assert_eq!(json["code"], "INVALID_STATE");
    let (status, _) = call(
        &app,
        "POST",
        &format!("/ips/byoip/{range_id}/verify"),
        Some(&token),
        Some(serde_json::json!({"verification_token": vtoken})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Log stream route: create with a secret → response masks it; verify an
    // unknown type is not auto-verified.
    let (status, json) = call(
        &app,
        "POST",
        "/log-streams",
        Some(&token),
        Some(serde_json::json!({
            "tenant_id": tenant, "name": "s", "destination_type": "splunk",
            "destination_config": {"url": "https://splunk.example.com:8088", "token": "abcd1234"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["destination_config"]["token"], "****1234");
    let stream_id = json["data"]["id"].as_str().unwrap().to_string();
    let (status, json) = call(
        &app,
        "GET",
        &format!("/log-streams/tenant/{tenant}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"].as_array().unwrap().len(), 1);
    let (status, json) = call(
        &app,
        "GET",
        &format!("/log-streams/{stream_id}/stats"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["total_deliveries"], 0);
    let (status, _) = call(
        &app,
        "POST",
        &format!("/log-streams/{stream_id}/pause"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        "POST",
        &format!("/log-streams/{stream_id}/resume"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/log-streams/{stream_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/log-streams/{stream_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
});

db_test!(
    routes_sub_accounts_templates_qbr_and_whitelabel_surface,
    pool,
    {
        let tenant = t26();
        seed_tenant(&pool, &tenant).await;
        let (app, token) = build_router(&pool, &tenant).await;

        // Sub-account create → get → list → stats → api key → revoke.
        let (status, json) = call(
            &app,
            "POST",
            "/sub-accounts",
            Some(&token),
            Some(serde_json::json!({"parent_id": tenant, "name": "agency", "volume_limit": 1000})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let sub_id = json["data"]["id"].as_str().unwrap().to_string();
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sub-accounts/{sub_id}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/sub-accounts/parent/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"].as_array().unwrap().len(), 1);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/sub-accounts/stats/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"]["total"], 1);
        let (status, json) = call(
            &app,
            "POST",
            &format!("/sub-accounts/{sub_id}/api-keys"),
            Some(&token),
            Some(serde_json::json!({"name": "ci", "permissions": ["send"]})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let key_id = json["data"]["id"].as_str().unwrap().to_string();
        let (status, json) = call(
            &app,
            "GET",
            &format!("/sub-accounts/{sub_id}/api-keys"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["data"][0]["key_hash"]
            .as_str()
            .unwrap_or("")
            .is_empty());
        let (status, _) = call(
            &app,
            "POST",
            &format!("/sub-accounts/{sub_id}/api-keys/{key_id}/revoke"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/sub-accounts/{sub_id}"),
            Some(&token),
            Some(serde_json::json!({"name": "renamed"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/sub-accounts/{sub_id}/suspend"),
            Some(&token),
            Some(serde_json::json!({"reason": "abuse"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/sub-accounts/{sub_id}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sub-accounts/{sub_id}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Templates: submit, list, change-request requires notes (400 when
        // missing/garbage), approve.
        let (status, json) = call(
            &app,
            "POST",
            "/templates/submit",
            Some(&token),
            Some(serde_json::json!({
                "tenant_id": tenant, "name": "t", "subject": "Hi",
                "html_content": "<p>Hello <a href=\"https://x.example/unsubscribe\">u</a></p>",
                "submitted_by": "author"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let template_id = json["data"]["id"].as_str().unwrap().to_string();
        let (status, json) = call(
            &app,
            "GET",
            &format!("/templates/tenant/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"].as_array().unwrap().len(), 1);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/templates/{template_id}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/templates/{template_id}/request-changes"),
            Some(&token),
            Some(serde_json::json!({"reviewed_by": "rev"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "notes are required");
        let (status, _) = call(
            &app,
            "POST",
            &format!("/templates/{template_id}/approve"),
            Some(&token),
            Some(serde_json::json!({"reviewed_by": "rev", "notes": "ok"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/templates/stats/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["data"]["approved"], 1);

        // QBR: schedule → list → generate → deliver → feedback → benchmarks.
        let (status, json) = call(
            &app,
            "POST",
            "/qbr",
            Some(&token),
            Some(serde_json::json!({"tenant_id": tenant, "quarter": 2, "year": 2026})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let qbr_id = json["data"]["id"].as_str().unwrap().to_string();
        let (status, json) = call(
            &app,
            "GET",
            &format!("/qbr/tenant/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"].as_array().unwrap().len(), 1);
        let (status, _) = call(&app, "GET", &format!("/qbr/{qbr_id}"), Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = call(
            &app,
            "POST",
            &format!("/qbr/{qbr_id}/generate"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, _) = call(
            &app,
            "POST",
            &format!("/qbr/{qbr_id}/deliver"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/qbr/{qbr_id}/feedback"),
            Some(&token),
            Some(serde_json::json!({"rating": 5, "feedback_text": "great"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/qbr/{qbr_id}/goals"),
            Some(&token),
            Some(serde_json::json!({"goal_id": Uuid::new_v4(), "current_value": 1.0})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(
            &app,
            "GET",
            "/qbr/benchmarks?industry=saas",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // White-label: config upsert + read, templates upsert (before config is
        // configured the GET is a 404), domains.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/whitelabel/config/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(
        &app,
        "PUT",
        "/whitelabel/config",
        Some(&token),
        Some(serde_json::json!({"tenant_id": tenant, "company_name": "Acme", "custom_css": "body{color:red}"})),
    )
    .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/whitelabel/config/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"]["company_name"], "Acme");

        let (status, _) = call(
        &app,
        "PUT",
        "/whitelabel/email-templates",
        Some(&token),
        Some(serde_json::json!({"tenant_id": tenant, "template_type": "welcome", "subject_template": "Hi"})),
    )
    .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/whitelabel/email-templates/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["data"].as_array().unwrap().len(), 1);

        let (status, json) = call(
        &app,
        "POST",
        "/whitelabel/domains",
        Some(&token),
        Some(serde_json::json!({"tenant_id": tenant, "domain": "mail.acme.example", "domain_type": "tracking"})),
    )
    .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let domain_id = json["data"]["id"].as_str().unwrap().to_string();
        let (status, json) = call(
            &app,
            "GET",
            &format!("/whitelabel/domains/tenant/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"].as_array().unwrap().len(), 1);
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/whitelabel/domains/{tenant}/{domain_id}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
);

db_test!(
    routes_compliance_encryption_zero_retention_and_metrics,
    pool,
    {
        let tenant = t26();
        seed_tenant(&pool, &tenant).await;
        let (app, token) = build_router(&pool, &tenant).await;

        // Enable compliance with a mix of frameworks (SOC2 forces encryption).
        let (status, json) = call(
            &app,
            "POST",
            "/compliance/enable",
            Some(&token),
            Some(serde_json::json!({"tenant_id": tenant, "frameworks": ["soc2", "gdpr"]})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, json) = call(
            &app,
            "GET",
            &format!("/compliance/config/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"]["encryption_at_rest"], true);
        // An unknown tenant id under a tenant-scoped token is refused as
        // forbidden-or-not-found, never disclosed.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/compliance/config/{}", t26()),
            Some(&token),
            None,
        )
        .await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
            "cross-tenant read must be refused, got {status}"
        );

        // Zero retention endpoint.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/compliance/zero-retention/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["data"]["zero_retention_mode"], true);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/compliance/zero-retention/{}", t26()),
            Some(&token),
            None,
        )
        .await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
            "cross-tenant zero-retention must be refused, got {status}"
        );

        // Encryption status surface.
        let (status, json) = call(
            &app,
            "GET",
            &format!("/compliance/encryption/status/{tenant}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["encryption_at_rest"], true);
        assert_eq!(json["encryption_in_transit"], true);
        assert_eq!(json["algorithm"], "AES-256-GCM");
        assert!(json["phi_fields"].as_array().unwrap().len() >= 5);

        // Encrypt/decrypt a PHI field round trip plus tamper resistance.
        let (status, json) = call(
            &app,
            "POST",
            "/compliance/encryption/encrypt-field",
            Some(&token),
            Some(serde_json::json!({
                "tenant_id": tenant, "field_name": "email",
                "value": "patient@example.com"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let ciphertext = json["value"].as_str().unwrap().to_string();
        assert_ne!(ciphertext, "patient@example.com");
        assert_eq!(json["is_phi"], true);
        let (status, json) = call(
            &app,
            "POST",
            "/compliance/encryption/decrypt-field",
            Some(&token),
            Some(serde_json::json!({
                "tenant_id": tenant, "field_name": "email",
                "value": ciphertext
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["value"], "patient@example.com");
        // A tampered ciphertext is refused, never silently mangled.
        let mut tampered = ciphertext.clone();
        tampered.push('A');
        let (status, json) = call(
            &app,
            "POST",
            "/compliance/encryption/decrypt-field",
            Some(&token),
            Some(serde_json::json!({
                "tenant_id": tenant, "field_name": "email",
                "value": tampered
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
        assert_eq!(json["error"]["code"], "DECRYPTION_FAILED");

        // Metrics requires either a token or loopback; without ConnectInfo the
        // request is not loopback → unauthorized.
        let (status, _) = call(&app, "GET", "/metrics", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
);
