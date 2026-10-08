//! Wave G: the statutory filing operator routes are MOUNTED (driven through
//! the real `create_router`), gated by the service bearer token, and exercise
//! the previously test-only filing builders against the canonical schema.

use super::*;
use crate::routes::create_router;
use crate::test_support;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

const TOKEN: &str = "statutory-wave-g-token";

async fn test_app(test_name: &str) -> Option<(axum::Router, sqlx::PgPool)> {
    let pool = test_support::canonical_pool(test_name, test_name).await?;
    let state = test_support::app_state(pool.clone(), TOKEN);
    Some((create_router(state), pool))
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };
    let response = app.clone().oneshot(request).await.expect("route response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn seed_oss_return(pool: &sqlx::PgPool) -> Uuid {
    let registration_id: Uuid = sqlx::query_scalar(
        "INSERT INTO oss_registrations (scheme, registration_country, registration_number, valid_from) \
         VALUES ('union', 'EE', $1, DATE '2025-01-01') RETURNING id",
    )
    .bind(format!(
        "EE-OSS-{}",
        &Uuid::new_v4().simple().to_string()[..8]
    ))
    .fetch_one(pool)
    .await
    .expect("insert OSS registration");

    let return_id: Uuid = sqlx::query_scalar(
        "INSERT INTO oss_returns \
            (registration_id, period, scheme, status, total_taxable_cents, total_vat_cents, \
             supply_count, payload_hash) \
         VALUES ($1, '2026-01', 'union', 'validated', 10000, 2400, 1, 'payload-hash-1') RETURNING id",
    )
    .bind(registration_id)
    .fetch_one(pool)
    .await
    .expect("insert OSS return");

    sqlx::query(
        "INSERT INTO oss_supply_entries \
            (registration_id, period, supply_id, tenant_id, customer_country, consumption_country, \
             taxable_amount_cents, vat_rate, vat_amount_cents, currency) \
         VALUES ($1, '2026-01', $2, 'tenant-1', 'DE', 'DE', 10000, 24.0, 2400, 'EUR')",
    )
    .bind(registration_id)
    .bind(format!("supply-{}", &Uuid::new_v4().simple().to_string()[..8]))
    .execute(pool)
    .await
    .expect("insert OSS supply entry");

    return_id
}

/// The routes exist on the real router and the bearer gate is enforced.
#[tokio::test]
async fn statutory_routes_are_mounted_and_gated() {
    let Some((app, _pool)) = test_app("statutory_gate").await else {
        return;
    };

    let (status, _) = send(
        &app,
        "GET",
        "/statutory/filings/human-tasks",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = send(
        &app,
        "GET",
        "/statutory/filings/human-tasks",
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["data"]["tasks"].is_array(), "{body}");
}

/// The OSS return package route returns the exact validated payload and its
/// digest; the incomplete/unknown cases answer honestly.
#[tokio::test]
async fn oss_package_route_builds_the_validated_payload() {
    let Some((app, pool)) = test_app("statutory_oss_package").await else {
        return;
    };
    let return_id = seed_oss_return(&pool).await;

    let (status, body) = send(
        &app,
        "GET",
        &format!("/statutory/filings/oss/{return_id}/package"),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["returnKind"], "oss", "{body}");
    assert_eq!(body["data"]["period"], "2026-01", "{body}");
    assert!(body["data"]["payload"].is_object(), "{body}");
    let digest = body["data"]["payloadSha256"].as_str().expect("digest");
    assert_eq!(digest.len(), 64, "{body}");

    // The digest is over the returned payload (deterministic package hash).
    let recomputed = filing_transport::package_hash(&body["data"]["payload"]);
    assert_eq!(recomputed, digest);

    // An unknown return is a 404; an unknown kind is a 400.
    let (status, _) = send(
        &app,
        "GET",
        &format!("/statutory/filings/oss/{}/package", Uuid::new_v4()),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(
        &app,
        "GET",
        "/statutory/filings/kmd/00000000-0000-0000-0000-000000000000/package",
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    pool.close().await;
}

/// Stored-package verification detects tampering with the recorded digest.
#[tokio::test]
async fn stored_package_verification_detects_tampering() {
    let Some((app, pool)) = test_app("statutory_verify_package").await else {
        return;
    };
    let return_id = seed_oss_return(&pool).await;

    let payload = filing_transport::build_package_payload(
        &pool,
        ReturnKind::Oss,
        return_id,
        "2026-01",
        Some("payload-hash-1"),
    )
    .await
    .expect("validated package");
    let digest = filing_transport::package_hash(&payload);
    let package_id: Uuid = sqlx::query_scalar(
        // `validation_outcome = 'valid'` + no named gaps is the recorded
        // evidence `verify_package_row` insists on (migration 226).
        "INSERT INTO filing_submission_packages \
            (return_kind, return_id, period, payload, payload_sha256, transport, status, \
             form, validation_outcome, named_gaps, timestamp_status) \
         VALUES ('oss', $1, '2026-01', $2, $3, 'human_task', 'queued', \
                 'oss', 'valid', '[]'::jsonb, 'not_configured') RETURNING id",
    )
    .bind(return_id)
    .bind(&payload)
    .bind(&digest)
    .fetch_one(&pool)
    .await
    .expect("insert package row");

    let (status, body) = send(
        &app,
        "POST",
        &format!("/statutory/filings/packages/{package_id}/verify"),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["verified"], true);

    sqlx::query("UPDATE filing_submission_packages SET payload = $2 WHERE id = $1")
        .bind(package_id)
        .bind(serde_json::json!({ "tampered": true }))
        .execute(&pool)
        .await
        .expect("tamper");
    let (status, body) = send(
        &app,
        "POST",
        &format!("/statutory/filings/packages/{package_id}/verify"),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    pool.close().await;
}

/// The TSD preview route runs the ledger derivation AND the TSD package
/// builder, returning the builder's named refusal for an unbooked month.
#[tokio::test]
async fn tsd_package_route_states_the_named_refusal() {
    let Some((app, pool)) = test_app("statutory_tsd_refusal").await else {
        return;
    };
    let registry_code = format!("8{}", &Uuid::new_v4().simple().to_string()[..7]);
    sqlx::query(
        "INSERT INTO legal_entities (legal_name, registry_code, country_code) \
         VALUES ('Wave G OÜ', $1, 'EE')",
    )
    .bind(&registry_code)
    .execute(&pool)
    .await
    .expect("insert legal entity");

    let (status, body) = send(
        &app,
        "GET",
        &format!("/statutory/tsd/{registry_code}/2026/1/package"),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["data"]["package"].is_null(), "{body}");
    let refusal = body["data"]["refusal"].as_str().expect("named refusal");
    assert!(
        !refusal.is_empty(),
        "the refusal must name the missing source data: {body}"
    );

    // An unknown registry code fails the derivation loudly, never silently.
    let (status, _) = send(
        &app,
        "GET",
        "/statutory/tsd/00000000/2026/1/package",
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // Month bounds are validated at the boundary.
    let (status, _) = send(
        &app,
        "GET",
        &format!("/statutory/tsd/{registry_code}/2026/13/package"),
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    pool.close().await;
}

/// The annual-report route exposes the two human legal acts with the required
/// evidence (authenticated actor + authority receipt reference).
#[tokio::test]
async fn annual_report_acts_require_actor_and_receipt() {
    let Some((app, pool)) = test_app("statutory_annual_report").await else {
        return;
    };
    let entity: Uuid = sqlx::query_scalar(
        "INSERT INTO legal_entities (legal_name, registry_code, country_code) \
         VALUES ('Annual Wave G OÜ', $1, 'EE') RETURNING id",
    )
    .bind(format!("9{}", &Uuid::new_v4().simple().to_string()[..7]))
    .fetch_one(&pool)
    .await
    .expect("insert entity");
    let period: Uuid = sqlx::query_scalar(
        "INSERT INTO fiscal_periods \
            (legal_entity_id, period_type, label, start_date, end_date, status) \
         VALUES ($1, 'year', '2025', DATE '2025-01-01', DATE '2025-12-31', 'closed') RETURNING id",
    )
    .bind(entity)
    .fetch_one(&pool)
    .await
    .expect("insert fiscal period");
    let report_id: Uuid = sqlx::query_scalar(
        "INSERT INTO annual_reports \
            (legal_entity_id, fiscal_period_id, fiscal_year, period_start, period_end, status, \
             generated_by, ledger_hash, xbrl_instance) \
         VALUES ($1, $2, 2025, DATE '2025-01-01', DATE '2025-12-31', 'draft', 'lib-test', $3, '') \
         RETURNING id",
    )
    .bind(entity)
    .bind(period)
    .bind("a".repeat(64))
    .fetch_one(&pool)
    .await
    .expect("insert annual report");

    // Approve without an actor is refused at the boundary.
    let (status, _) = send(
        &app,
        "POST",
        &format!("/statutory/annual-reports/{report_id}/approve"),
        Some(TOKEN),
        Some(serde_json::json!({ "actor": "  " })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = send(
        &app,
        "POST",
        &format!("/statutory/annual-reports/{report_id}/approve"),
        Some(TOKEN),
        Some(serde_json::json!({ "actor": "board:tester" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let approved: (String, Option<String>) =
        sqlx::query_as("SELECT status, approved_by FROM annual_reports WHERE id = $1")
            .bind(report_id)
            .fetch_one(&pool)
            .await
            .expect("report row");
    assert_eq!(approved.0, "management_approved");
    assert_eq!(approved.1.as_deref(), Some("board:tester"));

    // Submission without the authority receipt reference is refused.
    let (status, _) = send(
        &app,
        "POST",
        &format!("/statutory/annual-reports/{report_id}/submit"),
        Some(TOKEN),
        Some(serde_json::json!({ "actor": "filer:tester", "receiptReference": "  " })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = send(
        &app,
        "POST",
        &format!("/statutory/annual-reports/{report_id}/submit"),
        Some(TOKEN),
        Some(serde_json::json!({
            "actor": "filer:tester",
            "receiptReference": "AR-2025-0001"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let submitted: (String, Option<String>) = sqlx::query_as(
        "SELECT status, authority_receipt_reference FROM annual_reports WHERE id = $1",
    )
    .bind(report_id)
    .fetch_one(&pool)
    .await
    .expect("report row");
    assert_eq!(submitted.0, "submitted");
    assert_eq!(submitted.1.as_deref(), Some("AR-2025-0001"));

    // A second approval is a state-machine conflict (409), not a 500.
    let (status, _) = send(
        &app,
        "POST",
        &format!("/statutory/annual-reports/{report_id}/approve"),
        Some(TOKEN),
        Some(serde_json::json!({ "actor": "board:tester" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    pool.close().await;
}

/// The KMD INF annex validation route exercises the builder and states the
/// derivation gap (the package is advisory, never presented as filable).
#[tokio::test]
async fn kmd_inf_validation_route_exercises_the_builder() {
    let Some((app, pool)) = test_app("statutory_kmd_inf").await else {
        return;
    };

    let annex = serde_json::json!({
        "period": "2026-01",
        "entity": {
            "legal_name": "KMD INF OÜ",
            "registry_code": "12345678",
            "vat_number": "EE123456789",
            "registration_number": null
        },
        "lines": [{
            "invoice_number": "INV-1",
            "invoice_date": "2026-01-15",
            "counterparty_name": "Buyer OÜ",
            "counterparty_registry_code": "87654321",
            "counterparty_vat_number": null,
            "taxable_amount_cents": 150000,
            "vat_rate_percent": 24.0,
            "vat_amount_cents": 36000
        }]
    });

    let (status, body) = send(
        &app,
        "POST",
        "/statutory/kmd-inf/validate",
        Some(TOKEN),
        Some(annex.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["submittable"], false, "{body}");
    let gaps = body["data"]["namedGaps"].as_array().expect("named gaps");
    assert!(
        gaps.iter().any(|gap| gap["field"]
            == crate::filing_package::KMD_INF_DERIVATION_GAP),
        "the derivation gap must be stated: {body}"
    );
    assert!(body["data"]["package"]["payload"].is_object(), "{body}");

    // An annex without counterparty identity is refused with the field named.
    let mut invalid = annex;
    invalid["lines"][0]["counterparty_registry_code"] = serde_json::Value::Null;
    let (status, body) = send(
        &app,
        "POST",
        "/statutory/kmd-inf/validate",
        Some(TOKEN),
        Some(invalid),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("counterparty")),
        "{body}"
    );

    pool.close().await;
}
