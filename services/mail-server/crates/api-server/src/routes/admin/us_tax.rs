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
//! * `GET  /v1/admin/billing/us-tax/states` — the tracked states, the
//!   rate-file rows (with freshness), the reported-not-assigned sales
//!   (unknown-state and non-USD invoices) and the open threshold alerts.
//! * `POST /v1/admin/billing/us-tax/states/:state/registration` —
//!   `{"status":"registered"|"below","note":…}`: register (requires a
//!   present, fresh rate row — otherwise every invoice in that state would be
//!   refused) or unregister (deliberately independent of the file: a
//!   rate-file problem must never block REMOVING a tax).
//!
//! Nothing here charges anything: registering a state changes what FUTURE
//! invoices compute; it never touches an issued invoice.

use axum::extract::{Path, State};
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
/// operator can fix (bad code, missing/stale rate row, unusable data file) is
/// a 400; an untracked state is a 404; anything else is infrastructure.
fn map_registration_error(error: billing_service::us_tax::RegistrationError) -> ApiError {
    use billing_service::us_tax::RegistrationError as E;
    match error {
        E::UnknownState(message) => ApiError::BadRequest(message),
        E::UnusableRateRow { .. } => ApiError::Validation(vec![error.to_string()]),
        E::NotTracked { .. } => ApiError::NotFound(error.to_string()),
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
                "nexusWindow": row.nexus_window,
                "thresholdCents": row.threshold_cents,
                "observedCents": row.observed_cents,
                "windowStart": row.window_start,
                "windowEnd": row.window_end,
                "crossedAt": row.crossed_at,
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
            json!({
                "state": row.state,
                "rateBps": row.rate_bps,
                "nexusThresholdCents": row.nexus_threshold_cents,
                "nexusWindow": row.nexus_window.as_str(),
                "sourceUrl": row.source_url,
                "retrieved": row.retrieved,
                "ageDays": age_days,
                "fresh": billing_service::us_tax::is_row_fresh(row, today, config.max_age_days),
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

    let alerts: Vec<serde_json::Value> = sqlx::query_as::<_, (uuid::Uuid, String, serde_json::Value, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, severity, detail, created_at FROM finance_incidents \
         WHERE kind = $1 AND status = 'open' ORDER BY created_at DESC LIMIT 100",
    )
    .bind(billing_service::us_tax::NEXUS_ALERT_KIND)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from)?
    .into_iter()
    .map(|(id, severity, detail, created_at)| {
        json!({ "id": id, "severity": severity, "detail": detail, "createdAt": created_at })
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
        "thresholdCents": row.threshold_cents,
        "observedCents": row.observed_cents,
        "registeredAt": row.registered_at,
        "registeredBy": row.registered_by,
        "registrationNote": row.registration_note,
        // Stated on every mutation: nothing here is retroactive.
        "appliesTo": "invoices issued from now on; issued invoices are never changed",
    })))
}
