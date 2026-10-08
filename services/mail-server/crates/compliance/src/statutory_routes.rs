//! Statutory filing operator surface (dogfood wave G, audit B R-5).
//!
//! `filing_transport` and `annual_report` implement the audited human legal
//! acts (package build/verify, mandatory human tasks, annual-report
//! approval/submission), but until this module existed every caller was a
//! test: no route exposed them. The builders now have a real operator
//! surface:
//!
//! * `GET  /statutory/filings/human-tasks` — the open manual-submission queue
//!   (`open_human_tasks`).
//! * `GET  /statutory/filings/:kind/:return_id/package` — the exact validated
//!   submission payload for an OSS/VD return (`build_package_payload`),
//!   refused with the named problems when the form contract fails.
//! * `POST /statutory/filings/packages/:id/verify` — re-verify a stored
//!   package against its recorded digest (`verify_package_row`).
//! * `GET  /statutory/tsd/:registry_code/:year/:month/package` — the TSD
//!   package derived from the posted ledger (`tsd_ledger` ->
//!   `build_tsd_package`), returning EITHER the validated package OR the
//!   builder's named refusal (the TSD payment-type gap makes a valid package
//!   non-submittable; that is stated, never hidden).
//! * `POST /statutory/annual-reports/:id/approve` — the management approval
//!   act (`approve_annual_report`).
//! * `POST /statutory/annual-reports/:id/submit` — the submission act with
//!   the authority receipt reference (`record_annual_report_submission`).
//!
//! Authentication is the service bearer token (`verify_bearer`), the same
//! gate every other route in this service uses. Actor identities travel
//! explicitly in the request bodies (they are recorded on the legal acts and
//! must be identities the CALLER has authenticated upstream — the service
//! token is shared).

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::filing_transport::{self, ReturnKind};
use crate::routes::{err_json, ok_json, verify_bearer, AppState};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/statutory/filings/human-tasks", get(list_human_tasks))
        .route(
            "/statutory/filings/:kind/:return_id/package",
            get(build_return_package),
        )
        .route(
            "/statutory/filings/packages/:package_id/verify",
            post(verify_package),
        )
        .route(
            "/statutory/tsd/:registry_code/:year/:month/package",
            get(tsd_package),
        )
        .route("/statutory/kmd-inf/validate", post(validate_kmd_inf_annex))
        .route(
            "/statutory/annual-reports/:report_id/approve",
            post(approve_annual_report),
        )
        .route(
            "/statutory/annual-reports/:report_id/submit",
            post(submit_annual_report),
        )
}

#[derive(Debug, Deserialize)]
pub struct LimitQuery {
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /statutory/filings/human-tasks` — open manual filing tasks.
async fn list_human_tasks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<LimitQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match filing_transport::open_human_tasks(&state.db, params.limit.unwrap_or(100)).await {
        Ok(tasks) => Ok(ok_json(json!({ "tasks": tasks }))),
        Err(error) => {
            tracing::error!(error = %error, "filing human-task listing failed");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to list filing tasks",
            ))
        }
    }
}

/// `GET /statutory/filings/:kind/:return_id/package` — the validated
/// submission payload for a return (`kind` = `oss` | `vd`).
async fn build_return_package(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, return_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;

    let Some(kind) = ReturnKind::from_db(&kind) else {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "unknown return kind (expected oss or vd)",
        ));
    };
    let return_id = match Uuid::parse_str(&return_id) {
        Ok(id) => id,
        Err(_) => {
            return Err(err_json(
                StatusCode::BAD_REQUEST,
                "return_id must be a UUID",
            ))
        }
    };

    // The return's period is part of the package identity; load it from the
    // canonical return table (the same table the transport reads).
    let period: Option<String> = sqlx::query_scalar(&format!(
        "SELECT period FROM {} WHERE id = $1",
        kind.table()
    ))
    .bind(return_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "filing return lookup failed");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to load the return")
    })?;
    let Some(period) = period else {
        return Err(err_json(StatusCode::NOT_FOUND, "return not found"));
    };

    let payload_hash: Option<String> = sqlx::query_scalar(&format!(
        "SELECT payload_hash FROM {} WHERE id = $1",
        kind.table()
    ))
    .bind(return_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(None);

    match filing_transport::build_package_payload(
        &state.db,
        kind,
        return_id,
        &period,
        payload_hash.as_deref(),
    )
    .await
    {
        Ok(payload) => {
            let digest = filing_transport::package_hash(&payload);
            Ok(ok_json(json!({
                "returnKind": kind.as_str(),
                "returnId": return_id,
                "period": period,
                "payload": payload,
                "payloadSha256": digest,
            })))
        }
        // The builder refuses incomplete declarations with the offending
        // fields named; that is a caller-actionable 422, not a server fault.
        Err(error) => Err(err_json(StatusCode::UNPROCESSABLE_ENTITY, &error)),
    }
}

/// `POST /statutory/filings/packages/:package_id/verify` — recompute the
/// stored package digest and report whether the row still matches.
async fn verify_package(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(package_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let package_id = match Uuid::parse_str(&package_id) {
        Ok(id) => id,
        Err(_) => {
            return Err(err_json(
                StatusCode::BAD_REQUEST,
                "package_id must be a UUID",
            ))
        }
    };
    match filing_transport::verify_package_row(&state.db, package_id).await {
        Ok(()) => Ok(ok_json(json!({ "packageId": package_id, "verified": true }))),
        Err(error) => Err(err_json(StatusCode::UNPROCESSABLE_ENTITY, &error)),
    }
}

/// `GET /statutory/tsd/:registry_code/:year/:month/package` — the TSD
/// package derived from the entity's posted ledger.
///
/// The response is either the validated package (`"package"`) or the
/// builder's named refusal (`"refusal"`) — an unbooked month and the
/// payment-type gap are stated, never papered over.
async fn tsd_package(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((registry_code, year, month)): Path<(String, i32, u32)>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    if !(1..=12).contains(&month) {
        return Err(err_json(StatusCode::BAD_REQUEST, "month must be 1..=12"));
    }
    if registry_code.trim().is_empty() || registry_code.len() > 32 {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "registry_code must be 1..=32 characters",
        ));
    }

    let engine = crate::estonia_ou::EstoniaOuCompliance::new(state.db.clone());
    let declaration = engine
        .generate_social_tax_declaration_for_registry_code(&registry_code, year, month)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "TSD ledger derivation failed");
            err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to derive the TSD declaration from the ledger",
            )
        })?;

    match crate::filing_package::build_tsd_package(&declaration) {
        Ok(package) => Ok(ok_json(json!({
            "package": package,
            "refusal": serde_json::Value::Null,
        }))),
        Err(error) => Ok(ok_json(json!({
            "package": serde_json::Value::Null,
            "refusal": error.to_string(),
        }))),
    }
}

/// `POST /statutory/kmd-inf/validate` — validate a caller-supplied KMD INF
/// annex through `filing_package::build_kmd_inf_package`.
///
/// The annex has no repository derivation (the field-level source is the
/// operator's invoice extract), so the response carries the builder's
/// validated package AND its named `kmd_inf.invoice_lines_derivation` gap:
/// the package is an advisory validation, never presented as filable. The
/// live EMTA submission of KMD INF is the billing-service XML path.
async fn validate_kmd_inf_annex(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(annex): Json<crate::filing_package::KmdInfAnnex>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match crate::filing_package::build_kmd_inf_package(&annex) {
        Ok(package) => {
            let named_gaps = package.named_gaps.clone();
            Ok(ok_json(json!({
                "package": package,
                "namedGaps": named_gaps,
                "submittable": false,
            })))
        }
        Err(error) => Err(err_json(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string())),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnualApproveBody {
    /// Authenticated upstream actor identity (recorded on the legal act).
    pub actor: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnualSubmitBody {
    pub actor: String,
    /// Authority receipt reference (Äriregister confirmation).
    #[serde(rename = "receiptReference")]
    pub receipt_reference: String,
}

/// `POST /statutory/annual-reports/:report_id/approve` — the management
/// approval act (draft -> management_approved).
async fn approve_annual_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(report_id): Path<String>,
    Json(body): Json<AnnualApproveBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let report_id = match Uuid::parse_str(&report_id) {
        Ok(id) => id,
        Err(_) => {
            return Err(err_json(
                StatusCode::BAD_REQUEST,
                "report_id must be a UUID",
            ))
        }
    };
    if body.actor.trim().is_empty() {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "actor is required (the authenticated approver identity)",
        ));
    }
    match crate::annual_report::approve_annual_report(
        &state.db,
        report_id,
        body.actor.trim(),
        body.notes.as_deref(),
    )
    .await
    {
        Ok(()) => Ok(ok_json(json!({
            "reportId": report_id,
            "status": "management_approved",
        }))),
        Err(error) => Err(classify_annual_error(error)),
    }
}

/// `POST /statutory/annual-reports/:report_id/submit` — the submission act
/// (management_approved -> submitted) with the authority receipt reference.
async fn submit_annual_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(report_id): Path<String>,
    Json(body): Json<AnnualSubmitBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let report_id = match Uuid::parse_str(&report_id) {
        Ok(id) => id,
        Err(_) => {
            return Err(err_json(
                StatusCode::BAD_REQUEST,
                "report_id must be a UUID",
            ))
        }
    };
    if body.actor.trim().is_empty() {
        return Err(err_json(StatusCode::BAD_REQUEST, "actor is required"));
    }
    if body.receipt_reference.trim().is_empty() {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "receiptReference is required (authority confirmation)",
        ));
    }
    match crate::annual_report::record_annual_report_submission(
        &state.db,
        report_id,
        body.actor.trim(),
        body.receipt_reference.trim(),
        None,
    )
    .await
    {
        Ok(()) => Ok(ok_json(json!({
            "reportId": report_id,
            "status": "submitted",
            "receiptReference": body.receipt_reference,
        }))),
        Err(error) => Err(classify_annual_error(error)),
    }
}

/// A "not found" is a 404; every other refusal is a state-machine/validation
/// conflict the caller can act on (409) — never a masked 500.
fn classify_annual_error(error: String) -> (StatusCode, Json<serde_json::Value>) {
    let lower = error.to_ascii_lowercase();
    if lower.contains("not found") {
        err_json(StatusCode::NOT_FOUND, &error)
    } else {
        err_json(StatusCode::CONFLICT, &error)
    }
}

#[cfg(test)]
mod tests;
