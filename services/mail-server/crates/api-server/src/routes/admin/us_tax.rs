//! US sales-tax nexus administration — the operator surface for
//! `billing_service::us_tax` (plan WP C2).
//!
//! Two truths, both shown: the COMMITTED rate/threshold data file
//! (`billing-service/data/us_sales_tax.json`, validated and freshness-checked
//! on every read) and the per-state status rows the nexus sweep maintains
//! (`us_tax_nexus_states`). This module is the ONLY surface that can write
//! `status = 'registered'` — the sweep flips `below`/`threshold_crossed` and
//! raises the finance alert, but registering with a state is a legal act by
//! the owner/accounting, and only registration makes sales tax compute on new
//! invoices.
//!
//! Routes (mounted under `/v1/admin/*`, i.e. the system-tenant control plane
//! with the CP session policy and the `["*"]` operator scope):
//!
//! * `GET  /v1/admin/billing/us-tax/states` — the tracked states (both nexus
//!   measures, the declared criteria, the warning record), the rate-file rows
//!   (taxability, rates, freshness), the reported-not-assigned sales
//!   (unknown-state and non-USD invoices) and the open threshold alerts.
//! * `POST /v1/admin/billing/us-tax/states/:state/registration` —
//!   `{"status":"registered"|"below","note":…}`: register (requires a
//!   present, fresh, TAXABLE row with an intact nexus declaration —
//!   otherwise every invoice in that state would be refused) or unregister
//!   (deliberately independent of the file: a rate-file problem must never
//!   block REMOVING a tax).
//! * `GET  /v1/admin/billing/us-tax/exemptions[?tenantId=…]` — the customer
//!   exemption certificates on file.
//! * `POST /v1/admin/billing/us-tax/exemptions` —
//!   `{"tenantId","state","certificateId","expiresAt"?,"note"?}`: store
//!   (insert or replace) one certificate for (tenant, state).
//! * `DELETE /v1/admin/billing/us-tax/exemptions/:id` — remove one.
//! * `GET  /v1/admin/billing/us-tax/report?period=YYYY-MM[&format=csv]` —
//!   the filing-ready per-state report (JSON, or CSV with `format=csv`).
//!
//! Nothing here charges anything: registering a state / adding or removing an
//! exemption changes what FUTURE invoices compute; never an issued invoice.

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/states", get(list_states))
        .route("/states/:state/registration", post(set_registration))
        .route("/exemptions", get(list_exemptions).post(create_exemption))
        .route("/exemptions/:id", axum::routing::delete(delete_exemption))
        .route("/report", get(read_report))
}

/// The only statuses an operator may set: `threshold_crossed` is COMPUTED by
/// the sweep and must never be assigned by hand.
const OPERATOR_STATUSES: [&str; 2] = ["registered", "below"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetRegistrationBody {
    pub status: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// The authenticated operator recorded on the registration.
fn actor(auth: &AuthUser) -> String {
    auth.user_id.clone().unwrap_or_else(|| "system".to_string())
}

/// Map a registration failure to its HTTP shape: a validation problem the
/// operator can fix (bad code, missing/stale rate row, a not_taxable state,
/// an incomplete nexus declaration, an unusable data file) is a 400; an
/// untracked state is a 404; anything else is infrastructure.
fn map_registration_error(error: billing_service::us_tax::RegistrationError) -> ApiError {
    use billing_service::us_tax::RegistrationError as E;
    match error {
        E::UnknownState(message) => ApiError::BadRequest(message),
        E::UnusableRateRow { .. }
        | E::NotTaxableState { .. }
        | E::InvalidNexusDeclaration { .. } => ApiError::Validation(vec![error.to_string()]),
        E::NotTracked { .. } => ApiError::NotFound(error.to_string()),
        E::Database(message) => ApiError::Internal(message),
    }
}

/// Map an exemption failure to its HTTP shape.
fn map_exemption_error(error: billing_service::us_tax::ExemptionError) -> ApiError {
    use billing_service::us_tax::ExemptionError as E;
    match error {
        E::UnknownState(_)
        | E::InvalidCertificate(_)
        | E::InvalidExpiry(_)
        | E::UnknownTenant(_) => ApiError::Validation(vec![error.to_string()]),
        E::NotFound(_) => ApiError::NotFound(error.to_string()),
        E::Database(message) => ApiError::Internal(message),
    }
}

/// Best-effort attributed audit entry for a registration change.
async fn audit_registration(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    state_code: &str,
    details: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "us_tax_nexus_state",
        Some(state_code),
        details,
        None,
        None,
    )
    .await;
}

/// `GET /v1/admin/billing/us-tax/states` — the tracked states, the committed
/// rate-file rows and the open threshold alerts.
async fn list_states(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Wildcard operator scope (admin boundary test): the route file must
    // enforce it in addition to the mounted control-plane gate.
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let today = chrono::Utc::now().date_naive();
    let config = billing_service::us_tax::UsTaxConfig::from_env(today)
        .map_err(|error| ApiError::Internal(format!("US tax rate file unusable: {error}")))?;
    let rows = billing_service::us_tax::list_status_rows(&state.db)
        .await
        .map_err(ApiError::Internal)?;

    let states: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            json!({
                "state": row.state_code,
                "status": row.status,
                "criteria": row.criteria,
                "nexusWindow": row.nexus_window,
                "thresholdCents": row.threshold_cents,
                "transactionThreshold": row.transaction_threshold,
                "observedCents": row.observed_cents,
                "observedCount": row.observed_count,
                "observedExemptCents": row.observed_exempt_cents,
                "windowStart": row.window_start,
                "windowEnd": row.window_end,
                "crossedAt": row.crossed_at,
                "warnedAt": row.warned_at,
                "registeredAt": row.registered_at,
                "registeredBy": row.registered_by,
                "registrationNote": row.registration_note,
                "lastEvaluatedAt": row.last_evaluated_at,
                "lastEvaluationError": row.last_evaluation_error,
            })
        })
        .collect();

    let rate_rows: Vec<serde_json::Value> = config
        .table
        .rows()
        .iter()
        .map(|row| {
            let age_days = billing_service::us_tax::row_age_days(row, today);
            let used = row.effective_rate();
            let (criteria, nexus_error) = match row.nexus_declaration() {
                Ok(Some(declaration)) => (Some(declaration.criteria.as_str()), None),
                Ok(None) => (None, None),
                Err(reason) => (None, Some(reason)),
            };
            json!({
                "state": row.state,
                "taxability": row.taxability.as_str(),
                "taxabilityNotice": row.taxability_notice,
                "unusedFiguresNotice": row.unused_figures_notice,
                "rateBps": row.rate_bps,
                "combinedRateBps": row.combined_rate_bps,
                "combinedSourceUrl": row.combined_source_url,
                "combinedRetrieved": row.combined_retrieved,
                "usedRateBps": used.as_ref().map(|rate| rate.rate_bps),
                "usedRateKind": used.as_ref().map(|rate| rate.kind.as_str()),
                "nexusThresholdCents": row.nexus_threshold_cents,
                "transactionThreshold": row.transaction_threshold,
                "criteria": criteria,
                "nexusDeclarationError": nexus_error,
                "nexusWindow": row.nexus_window.map(|window| window.as_str()),
                "sourceUrl": row.source_url,
                "retrieved": row.retrieved,
                "ageDays": age_days,
                "fresh": billing_service::us_tax::is_row_fresh(row, today, config.max_age_days),
                "warnFractionBps": config.warn_fraction_bps,
                "notes": row.notes,
            })
        })
        .collect();

    // The invoices the sweep can only REPORT: a US invoice whose billing
    // address carries no recognisable state, or one in a currency other than
    // USD (never converted — the thresholds are USD figures). Shown here so
    // "reported, never assigned" is visible to the operator, not just in logs.
    let reported = billing_service::us_tax::unassigned_us_sales(&state.db, chrono::Utc::now())
        .await
        .map_err(ApiError::Internal)?;

    // Both open incident kinds: the exactly-once crossing alert (high) and
    // the early warning at the configured fraction (medium) — the operator
    // sees the lead time, not just the crossing.
    let alerts: Vec<serde_json::Value> = sqlx::query_as::<
        _,
        (
            uuid::Uuid,
            String,
            String,
            serde_json::Value,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id, kind, severity, detail, created_at FROM finance_incidents \
         WHERE kind IN ($1, $2) AND status = 'open' ORDER BY created_at DESC LIMIT 100",
    )
    .bind(billing_service::us_tax::NEXUS_ALERT_KIND)
    .bind(billing_service::us_tax::NEXUS_WARNING_KIND)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from)?
    .into_iter()
    .map(|(id, kind, severity, detail, created_at)| {
        json!({
            "id": id,
            "kind": kind,
            "severity": severity,
            "detail": detail,
            "createdAt": created_at,
        })
    })
    .collect();

    Ok(Json(json!({
        "states": states,
        "rateFile": {
            "source": config.source,
            "maxAgeDays": config.max_age_days,
            "today": today,
            "states": rate_rows,
        },
        "reportedSales": {
            "window": "trailing_12m",
            "unknownStateInvoices": reported.unknown_state_invoices,
            "unknownStateCents": reported.unknown_state_cents,
            "nonUsdInvoices": reported
                .non_usd_invoices
                .iter()
                .map(|(currency, invoices, cents)| {
                    json!({ "currency": currency, "invoices": invoices, "taxableCents": cents })
                })
                .collect::<Vec<_>>(),
        },
        "thresholdAlerts": alerts,
        "registrationIsOperatorAction": true,
    })))
}

/// `POST /v1/admin/billing/us-tax/states/:state/registration` — register the
/// state (tax now computes on new invoices there) or unregister it.
async fn set_registration(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(state_code): Path<String>,
    Json(body): Json<SetRegistrationBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Wildcard operator scope (admin boundary test): the route file must
    // enforce it in addition to the mounted control-plane gate.
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    let status = body.status.trim().to_ascii_lowercase();
    if !OPERATOR_STATUSES.contains(&status.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "status must be one of: {} (threshold_crossed is computed by the sweep \
             and cannot be assigned)",
            OPERATOR_STATUSES.join(", ")
        )));
    }
    let normalized = state_code.trim().to_ascii_uppercase();
    if normalized.len() != 2 || !normalized.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(ApiError::BadRequest(
            "state must be a two-letter US state/territory code".into(),
        ));
    }
    if body
        .note
        .as_deref()
        .is_some_and(|note| note.chars().count() > 1_000)
    {
        return Err(ApiError::BadRequest(
            "note must be ≤ 1000 characters".into(),
        ));
    }

    let now = chrono::Utc::now();
    let actor = actor(&auth);
    let row = if status == "registered" {
        // Registration requires a present, FRESH rate row: without one every
        // new invoice in this state would be refused by the writer.
        let config =
            billing_service::us_tax::UsTaxConfig::from_env(now.date_naive()).map_err(|error| {
                ApiError::Validation(vec![format!(
                    "US tax rate file unusable (fix the file before registering): {error}"
                )])
            })?;
        billing_service::us_tax::register_state(
            &state.db,
            &config,
            &normalized,
            &actor,
            body.note.as_deref(),
            now,
        )
        .await
        .map_err(map_registration_error)?
    } else {
        billing_service::us_tax::unregister_state(
            &state.db,
            &normalized,
            &actor,
            body.note.as_deref(),
            now,
        )
        .await
        .map_err(map_registration_error)?
    };

    audit_registration(
        &state,
        &auth,
        if status == "registered" {
            "billing.us_tax_state_registered"
        } else {
            "billing.us_tax_state_unregistered"
        },
        &row.state_code,
        json!({
            "status": row.status,
            "note": body.note,
            "observedCents": row.observed_cents,
            "thresholdCents": row.threshold_cents,
            "windowStart": row.window_start,
            "windowEnd": row.window_end,
        }),
    )
    .await;

    Ok(Json(json!({
        "state": row.state_code,
        "status": row.status,
        "nexusWindow": row.nexus_window,
        "criteria": row.criteria,
        "thresholdCents": row.threshold_cents,
        "transactionThreshold": row.transaction_threshold,
        "observedCents": row.observed_cents,
        "observedCount": row.observed_count,
        "observedExemptCents": row.observed_exempt_cents,
        "registeredAt": row.registered_at,
        "registeredBy": row.registered_by,
        "registrationNote": row.registration_note,
        // Stated on every mutation: nothing here is retroactive.
        "appliesTo": "invoices issued from now on; issued invoices are never changed",
    })))
}

// ---------------------------------------------------------------------------
// Customer exemption certificates
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListExemptionsQuery {
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateExemptionBody {
    pub tenant_id: String,
    pub state: String,
    pub certificate_id: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

fn exemption_json(row: &billing_service::us_tax::UsTaxExemptionRow) -> serde_json::Value {
    json!({
        "id": row.id,
        "tenantId": row.tenant_id,
        "state": row.state_code,
        "certificateId": row.certificate_id,
        "expiresAt": row.expires_at,
        "note": row.note,
        "createdBy": row.created_by,
        "createdAt": row.created_at,
        "updatedAt": row.updated_at,
    })
}

/// `GET /v1/admin/billing/us-tax/exemptions` — every certificate on file,
/// optionally filtered to one tenant.
async fn list_exemptions(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<ListExemptionsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    let rows = billing_service::us_tax::list_exemptions(&state.db, query.tenant_id.as_deref())
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(json!({
        "exemptions": rows.iter().map(exemption_json).collect::<Vec<_>>(),
        "expiredNowNote": "a certificate whose expiresAt is before the invoice date never \
                           exempts; expiresAt null means the certificate states no expiry date",
    })))
}

/// `POST /v1/admin/billing/us-tax/exemptions` — store (insert or replace) one
/// certificate for (tenant, state). Applied to invoices issued from now on.
async fn create_exemption(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateExemptionBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    let tenant_id = body.tenant_id.trim();
    if tenant_id.is_empty() {
        return Err(ApiError::BadRequest("tenantId must not be empty".into()));
    }
    let expires_at = match body.expires_at.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => Some(
            chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d").map_err(|error| {
                ApiError::BadRequest(format!(
                    "expiresAt {raw:?} is not a YYYY-MM-DD date: {error}"
                ))
            })?,
        ),
    };
    let input = billing_service::us_tax::ExemptionInput {
        tenant_id: tenant_id.to_string(),
        state: body.state.clone(),
        certificate_id: body.certificate_id.clone(),
        expires_at,
        note: body.note.clone(),
    };
    let actor = actor(&auth);
    let row =
        billing_service::us_tax::upsert_exemption(&state.db, &input, &actor, chrono::Utc::now())
            .await
            .map_err(map_exemption_error)?;
    audit_registration(
        &state,
        &auth,
        "billing.us_tax_exemption_stored",
        &row.state_code,
        json!({
            "exemptionId": row.id,
            "tenantId": row.tenant_id,
            "certificateId": row.certificate_id,
            "expiresAt": row.expires_at,
            "note": row.note,
        }),
    )
    .await;
    Ok(Json(json!({
        "exemption": exemption_json(&row),
        "appliesTo": "invoices issued from now on; issued invoices are never changed",
    })))
}

/// `DELETE /v1/admin/billing/us-tax/exemptions/:id` — remove one certificate;
/// new invoices in the state are taxable again.
async fn delete_exemption(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    let actor = actor(&auth);
    let row = billing_service::us_tax::delete_exemption(&state.db, id, &actor)
        .await
        .map_err(map_exemption_error)?;
    audit_registration(
        &state,
        &auth,
        "billing.us_tax_exemption_deleted",
        &row.state_code,
        json!({
            "exemptionId": row.id,
            "tenantId": row.tenant_id,
            "certificateId": row.certificate_id,
        }),
    )
    .await;
    Ok(Json(json!({
        "deleted": exemption_json(&row),
        "appliesTo": "invoices issued from now on; issued invoices are never changed",
    })))
}

// ---------------------------------------------------------------------------
// Filing-ready report
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportQuery {
    pub period: String,
    #[serde(default)]
    pub format: Option<String>,
}

/// `GET /v1/admin/billing/us-tax/report?period=YYYY-MM[&format=csv]` — the
/// filing-ready per-state report the accountant consumes; `format=csv`
/// returns the CSV rendering.
async fn read_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<ReportQuery>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    let period = billing_service::us_tax::UsTaxReportPeriod::parse(&query.period)
        .map_err(|message| ApiError::Validation(vec![message]))?;
    let format = query
        .format
        .as_deref()
        .map(|format| format.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "json".to_string());
    if format != "json" && format != "csv" {
        return Err(ApiError::BadRequest(format!(
            "format must be \"json\" or \"csv\", got {:?}",
            query.format.as_deref().unwrap_or_default()
        )));
    }
    let report = billing_service::us_tax::us_tax_report(&state.db, period, chrono::Utc::now())
        .await
        .map_err(ApiError::Internal)?;
    if format == "csv" {
        return Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
            report.to_csv(),
        )
            .into_response());
    }
    Ok(Json(report.to_json()).into_response())
}

// ---------------------------------------------------------------------------
// Adversarial route tests: the operator surface over the REAL router.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use crate::app::test_support::adv::AdvEnv;

    async fn seed_tenant(pool: &sqlx::PgPool, id: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
             VALUES ($1, 'US tax admin fixture', $2, 'growth', 'active', NOW(), NOW())",
        )
        .bind(id)
        .bind(format!("slug-{id}"))
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    /// The customer-exemption surface: store → list → delete, every mutation
    /// audited, validation refusals named, control-plane only.
    #[tokio::test]
    async fn exemption_surface_stores_lists_deletes_and_audits() {
        let Some(pool) = crate::test_db::canonical_pool("admin_us_tax_exemptions").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tenant = "us_tax_exempt_admin01";
        seed_tenant(&pool, tenant).await;

        // Store a certificate (a multi-state certificate is stored per state).
        let (status, body) = env
            .post(
                "/v1/admin/billing/us-tax/exemptions",
                &json!({
                    "tenantId": tenant,
                    "state": "ca",
                    "certificateId": "MTC-4242",
                    "expiresAt": "2027-03-31",
                    "note": "resale certificate"
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["exemption"]["state"], "CA", "normalised");
        assert_eq!(body["exemption"]["certificateId"], "MTC-4242");
        assert_eq!(body["exemption"]["expiresAt"], "2027-03-31");
        let exemption_id = body["exemption"]["id"].as_str().expect("id").to_string();

        // Listed (and filterable by tenant).
        let (status, body) = env
            .get(&format!(
                "/v1/admin/billing/us-tax/exemptions?tenantId={tenant}"
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["exemptions"].as_array().expect("array").len(), 1);

        // Validation refusals, each named.
        for (payload, needle) in [
            (
                json!({"tenantId": tenant, "state": "California", "certificateId": "X"}),
                "state/territory postal code",
            ),
            (
                json!({"tenantId": tenant, "state": "CA", "certificateId": "   "}),
                "certificateId is empty",
            ),
            (
                json!({"tenantId": "no_such_tenant_0000000000", "state": "CA",
                       "certificateId": "X"}),
                "does not exist",
            ),
            (
                json!({"tenantId": tenant, "state": "CA", "certificateId": "X",
                       "expiresAt": "31/03/2027"}),
                "YYYY-MM-DD",
            ),
        ] {
            let (status, body) = env
                .post("/v1/admin/billing/us-tax/exemptions", &payload.to_string())
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{payload} → {body}");
            let rendered = body.to_string();
            assert!(rendered.contains(needle), "{payload} → {rendered}");
        }

        // The stored certificate is audited, attributed to the operator.
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs \
             WHERE action = 'billing.us_tax_exemption_stored' AND resource_id = 'CA' \
               AND details->>'certificateId' = 'MTC-4242'",
        )
        .fetch_one(&pool)
        .await
        .expect("audit rows");
        assert_eq!(audited, 1, "the store is audited");

        // Delete: audited, then gone; a second delete is a 404.
        let (status, body) = env
            .delete(&format!(
                "/v1/admin/billing/us-tax/exemptions/{exemption_id}"
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["deleted"]["certificateId"], "MTC-4242");
        let deleted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs \
             WHERE action = 'billing.us_tax_exemption_deleted' AND resource_id = 'CA'",
        )
        .fetch_one(&pool)
        .await
        .expect("audit rows");
        assert_eq!(deleted, 1, "the delete is audited");
        let (status, _body) = env
            .delete(&format!(
                "/v1/admin/billing/us-tax/exemptions/{exemption_id}"
            ))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Control-plane only: a customer credential never reaches the surface.
        let (customer_env, _tenant_id) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let (status, _body) = customer_env
            .get("/v1/admin/billing/us-tax/exemptions")
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a tenant credential must not reach the control plane"
        );
    }

    /// Registration stays operator-only and fails closed: with the committed
    /// (empty) rate file no state has a usable row, `threshold_crossed` is
    /// never assignable by hand, and the status read shows the two truths.
    #[tokio::test]
    async fn registration_fails_closed_and_only_operator_statuses_apply() {
        let Some(pool) = crate::test_db::canonical_pool("admin_us_tax_registration").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;

        // The status read serves both truths: no tracked states, the
        // committed file's rows (none) and the warn fraction.
        let (status, body) = env.get("/v1/admin/billing/us-tax/states").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["states"].as_array().expect("states").len(), 0);
        assert_eq!(
            body["rateFile"]["states"]
                .as_array()
                .expect("file rows")
                .len(),
            0
        );
        assert_eq!(body["rateFile"]["maxAgeDays"], 120);
        assert_eq!(body["registrationIsOperatorAction"], true);

        // Registering a state with no usable row is refused by NAME (the
        // state's invoices would be refused, so the row must land first).
        let (status, body) = env
            .post(
                "/v1/admin/billing/us-tax/states/CA/registration",
                &json!({ "status": "registered" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let rendered = body.to_string();
        assert!(rendered.contains("NO rate row"), "{rendered}");

        // `threshold_crossed` is computed by the sweep, never assigned.
        let (status, body) = env
            .post(
                "/v1/admin/billing/us-tax/states/CA/registration",
                &json!({ "status": "threshold_crossed" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.to_string().contains("threshold_crossed"), "{body}");

        // A malformed state code is refused.
        let (status, _body) = env
            .post(
                "/v1/admin/billing/us-tax/states/California/registration",
                &json!({ "status": "registered" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The filing report is served from the database: JSON by default, CSV on
    /// request, a strict period, and the figures the accountant needs.
    #[tokio::test]
    async fn filing_report_serves_json_and_csv_from_the_database() {
        let Some(pool) = crate::test_db::canonical_pool("admin_us_tax_report").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tenant = "us_tax_report_admin01";
        seed_tenant(&pool, tenant).await;
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, invoice_number, status, currency, amount, \
             subtotal, vat_total, us_sales_tax_cents, us_sales_tax_snapshot, total, issued_at, \
             billing_country, billing_address, created_at, updated_at) \
             VALUES (gen_random_uuid(), $1, 'USTAX-REPORT-1', 'pending', 'usd', 10725, 10000, \
                     0, 725, $2::jsonb, 10725, NOW(), 'US', '{\"state\":\"CA\"}', NOW(), NOW())",
        )
        .bind(tenant)
        .bind(
            json!({
                "snapshotVersion": 2, "state": "CA", "rateBps": 725, "rateKind": "state",
                "stateRateBps": 725, "combinedRateBps": null, "amountCents": 725,
                "source": "https://example.gov/us-tax-fixture", "retrieved": "2026-10-15"
            })
            .to_string(),
        )
        .execute(&pool)
        .await
        .expect("seed taxed invoice");

        let period = chrono::Utc::now().format("%Y-%m").to_string();
        let (status, body) = env
            .get(&format!("/v1/admin/billing/us-tax/report?period={period}"))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["period"], period);
        let states = body["states"].as_array().expect("states");
        let ca = states
            .iter()
            .find(|row| row["state"] == "CA")
            .expect("CA row");
        assert_eq!(ca["invoiceCount"], 1);
        assert_eq!(ca["grossSalesCents"], 10_000);
        assert_eq!(ca["taxCollectedCents"], 725);
        assert_eq!(ca["ratesUsed"][0]["rateBps"], 725);
        assert_eq!(body["totals"]["taxCollectedCents"], 725);
        assert!(body["rateFile"]["source"].is_string());

        // CSV on request, with the right content type.
        let (status, headers, bytes) = env
            .get_raw(&format!(
                "/v1/admin/billing/us-tax/report?period={period}&format=csv"
            ))
            .await;
        assert_eq!(status, StatusCode::OK);
        let content_type = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(content_type.starts_with("text/csv"), "{content_type}");
        let csv = String::from_utf8(bytes).expect("utf8");
        assert!(
            csv.starts_with("state,taxability,registrationStatus"),
            "{csv}"
        );
        assert!(csv.contains("CA,"), "{csv}");
        assert!(csv.contains("TOTAL,,,"), "{csv}");

        // A period is never guessed; the format is strict.
        for (query, needle) in [
            ("period=2026-13", "period"),
            ("period=2026-10-01", "period"),
            (format!("period={period}&format=pdf").as_str(), "format"),
        ] {
            let (status, body) = env
                .get(&format!("/v1/admin/billing/us-tax/report?{query}"))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query} → {body}");
            let rendered = body.to_string();
            assert!(rendered.contains(needle), "{query} → {rendered}");
        }
    }
}
