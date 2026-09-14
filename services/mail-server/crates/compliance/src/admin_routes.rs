//! Admin and public-facing routes for SOC2, HIPAA, and Trust Portal.
//!
//! Admin routes are gated by the standard compliance Bearer token and live
//! under `/v1/admin/{soc2,hipaa,trust}/...`.  Public routes for the Trust
//! Portal status page live under `/trust/...` and require **no auth**.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use tracing::error;

use crate::hipaa::{CountersignBaaInput, SignBaaInput};
use crate::routes::{created_json, err_json, ok_json, verify_bearer, AppState};
use crate::security_questionnaires::{
    framework_catalog, generate_questionnaire, generate_security_review_report,
    QuestionnaireContext, QuestionnaireFramework, QuestionnaireGenerationRequest,
};
use crate::soc2::ControlStatus;
use crate::trust_portal::{AccessRequestInput, DocumentInput, IncidentInput, SubprocessorInput};

// ─── Routers ───────────────────────────────────────────────────────────────

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        // SOC 2
        .route("/v1/admin/soc2/seed", post(soc2_seed_controls))
        .route("/v1/admin/soc2/controls", get(soc2_list_controls))
        .route("/v1/admin/soc2/controls/:control_id", get(soc2_get_control))
        .route(
            "/v1/admin/soc2/controls/:control_id/status",
            post(soc2_update_status),
        )
        .route(
            "/v1/admin/soc2/controls/:control_id/evidence",
            get(soc2_list_evidence),
        )
        .route("/v1/admin/soc2/run", post(soc2_run_collectors))
        // HIPAA
        .route(
            "/v1/admin/hipaa/baas",
            post(hipaa_request_baa).get(hipaa_list_baas),
        )
        .route("/v1/admin/hipaa/baas/:baa_id", get(hipaa_get_baa))
        .route("/v1/admin/hipaa/baas/:baa_id/sign", post(hipaa_sign))
        .route(
            "/v1/admin/hipaa/baas/:baa_id/countersign",
            post(hipaa_countersign),
        )
        .route(
            "/v1/admin/hipaa/baas/:baa_id/activate",
            post(hipaa_activate),
        )
        .route(
            "/v1/admin/hipaa/baas/:baa_id/terminate",
            post(hipaa_terminate),
        )
        .route(
            "/v1/admin/hipaa/tenants/:tenant_id/active",
            get(hipaa_active_for_tenant),
        )
        // Trust portal — admin
        .route(
            "/v1/admin/trust/documents",
            post(trust_upsert_document).get(trust_list_documents_admin),
        )
        .route(
            "/v1/admin/trust/documents/:slug/:version/supersede",
            post(trust_supersede_document),
        )
        .route(
            "/v1/admin/trust/subprocessors",
            post(trust_upsert_subprocessor).get(trust_list_subprocessors_admin),
        )
        .route(
            "/v1/admin/trust/subprocessors/:name",
            axum::routing::delete(trust_remove_subprocessor),
        )
        .route(
            "/v1/admin/trust/incidents",
            post(trust_create_incident).get(trust_list_incidents_admin),
        )
        .route(
            "/v1/admin/trust/incidents/:incident_id/updates",
            post(trust_post_incident_update).get(trust_list_incident_updates),
        )
        .route(
            "/v1/admin/trust/access-requests",
            get(trust_list_access_requests),
        )
        .route(
            "/v1/admin/trust/access-requests/:request_id/grant",
            post(trust_grant_access),
        )
        .route(
            "/v1/admin/trust/access-requests/:request_id/revoke",
            post(trust_revoke_access),
        )
        .route(
            "/v1/admin/trust/questionnaires/frameworks",
            get(trust_questionnaire_frameworks),
        )
        .route(
            "/v1/admin/trust/questionnaires/:framework/generate",
            post(trust_generate_questionnaire),
        )
        .route(
            "/v1/admin/trust/security-review-report",
            post(trust_generate_security_review_report),
        )
}

pub fn public_trust_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/trust/overview", get(public_trust_overview))
        .route("/trust/documents", get(public_trust_documents))
        .route("/trust/documents/:slug", get(public_trust_document_by_slug))
        .route("/trust/subprocessors", get(public_trust_subprocessors))
        .route("/trust/incidents", get(public_trust_incidents))
        .route("/trust/access-request", post(public_trust_access_request))
}

// ─── Common types ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<i64>,
}

// ─── SOC 2 handlers ────────────────────────────────────────────────────────

async fn soc2_seed_controls(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    state.soc2.seed_default_controls().await.map_err(|e| {
        error!("soc2 seed failed: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "seed failed")
    })?;
    Ok(ok_json(serde_json::json!({"seeded": true})))
}

async fn soc2_list_controls(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let controls = state.soc2.list_controls().await.map_err(|e| {
        error!("soc2 list failed: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
    })?;
    Ok(ok_json(controls))
}

async fn soc2_get_control(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(control_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.soc2.get_control(&control_id).await {
        Ok(Some(c)) => Ok(ok_json(c)),
        Ok(None) => Err(err_json(StatusCode::NOT_FOUND, "control not found")),
        Err(e) => {
            error!("soc2 get failed: {e}");
            Err(err_json(StatusCode::INTERNAL_SERVER_ERROR, "get failed"))
        }
    }
}

#[derive(Deserialize)]
struct UpdateStatusBody {
    status: String,
}

async fn soc2_update_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(control_id): Path<String>,
    Json(body): Json<UpdateStatusBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let status = match body.status.as_str() {
        "in_scope" => ControlStatus::InScope,
        "not_applicable" => ControlStatus::NotApplicable,
        "deferred" => ControlStatus::Deferred,
        other => {
            return Err(err_json(
                StatusCode::BAD_REQUEST,
                &format!("invalid status '{other}'"),
            ));
        }
    };
    state
        .soc2
        .set_status(&control_id, status)
        .await
        .map_err(|e| {
            error!("soc2 set_status failed: {e}");
            err_json(StatusCode::BAD_REQUEST, "update failed")
        })?;
    Ok(ok_json(serde_json::json!({"updated": true})))
}

#[derive(Deserialize)]
struct EvidenceQuery {
    limit: Option<i64>,
}

async fn soc2_list_evidence(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(control_id): Path<String>,
    Query(q): Query<EvidenceQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let evidence = state
        .soc2
        .list_evidence_for_control(&control_id, limit)
        .await
        .map_err(|e| {
            error!("soc2 list_evidence failed: {e}");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "evidence list failed")
        })?;
    Ok(ok_json(evidence))
}

#[derive(Deserialize, Default)]
struct RunBody {
    period_start: Option<DateTime<Utc>>,
    period_end: Option<DateTime<Utc>>,
}

async fn soc2_run_collectors(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<RunBody>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let RunBody {
        period_start,
        period_end,
    } = body.map(|Json(b)| b).unwrap_or_default();
    let now = Utc::now();
    let start = period_start.unwrap_or(now - Duration::days(1));
    let end = period_end.unwrap_or(now);
    let summary = state
        .soc2
        .run_automated_collectors(start, end)
        .await
        .map_err(|e| {
            error!("soc2 run failed: {e}");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "run failed")
        })?;
    Ok(ok_json(summary))
}

// ─── HIPAA handlers ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RequestBaaBody {
    tenant_id: String,
    version: String,
    actor: String,
}

async fn hipaa_request_baa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RequestBaaBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let baa = state
        .hipaa
        .request_baa(&body.tenant_id, &body.version, &body.actor)
        .await
        .map_err(|e| {
            error!("hipaa request failed: {e}");
            err_json(StatusCode::BAD_REQUEST, "request failed")
        })?;
    Ok(created_json(baa))
}

#[derive(Deserialize)]
struct ListBaaQuery {
    tenant_id: Option<String>,
}

async fn hipaa_list_baas(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ListBaaQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = q.tenant_id.ok_or_else(|| {
        err_json(
            StatusCode::BAD_REQUEST,
            "tenant_id query parameter required",
        )
    })?;
    let baas = state.hipaa.list_for_tenant(&tenant_id).await.map_err(|e| {
        error!("hipaa list failed: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
    })?;
    Ok(ok_json(baas))
}

async fn hipaa_get_baa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(baa_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.hipaa.fetch(&baa_id).await {
        Ok(Some(b)) => Ok(ok_json(b)),
        Ok(None) => Err(err_json(StatusCode::NOT_FOUND, "baa not found")),
        Err(e) => {
            error!("hipaa get failed: {e}");
            Err(err_json(StatusCode::INTERNAL_SERVER_ERROR, "get failed"))
        }
    }
}

#[derive(Deserialize)]
struct ActorBody {
    actor: String,
}

#[derive(Deserialize)]
struct SignBody {
    actor: String,
    #[serde(flatten)]
    input: SignBaaInput,
}

async fn hipaa_sign(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(baa_id): Path<String>,
    Json(body): Json<SignBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let baa = state
        .hipaa
        .sign(&baa_id, &body.actor, body.input)
        .await
        .map_err(|e| {
            error!("hipaa sign failed: {e}");
            err_json(StatusCode::BAD_REQUEST, "sign failed")
        })?;
    Ok(ok_json(baa))
}

#[derive(Deserialize)]
struct CountersignBody {
    actor: String,
    #[serde(flatten)]
    input: CountersignBaaInput,
}

async fn hipaa_countersign(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(baa_id): Path<String>,
    Json(body): Json<CountersignBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let baa = state
        .hipaa
        .countersign(&baa_id, &body.actor, body.input)
        .await
        .map_err(|e| {
            error!("hipaa countersign failed: {e}");
            err_json(StatusCode::BAD_REQUEST, "countersign failed")
        })?;
    Ok(ok_json(baa))
}

async fn hipaa_activate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(baa_id): Path<String>,
    Json(body): Json<ActorBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let baa = state
        .hipaa
        .activate(&baa_id, &body.actor)
        .await
        .map_err(|e| {
            error!("hipaa activate failed: {e}");
            err_json(StatusCode::BAD_REQUEST, "activate failed")
        })?;
    Ok(ok_json(baa))
}

#[derive(Deserialize)]
struct TerminateBody {
    actor: String,
    reason: String,
}

async fn hipaa_terminate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(baa_id): Path<String>,
    Json(body): Json<TerminateBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    if body.reason.trim().is_empty() {
        // Terminating a legal agreement without a recorded reason leaves the
        // evidence trail unexplained; refuse before touching the row.
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "termination requires a reason",
        ));
    }
    let baa = state
        .hipaa
        .terminate(&baa_id, &body.actor, &body.reason)
        .await
        .map_err(|e| {
            error!("hipaa terminate failed: {e}");
            err_json(StatusCode::BAD_REQUEST, "terminate failed")
        })?;
    Ok(ok_json(baa))
}

async fn hipaa_active_for_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let active = state.hipaa.is_active_for_tenant(&tenant_id).await;
    Ok(ok_json(serde_json::json!({
        "tenant_id": tenant_id,
        "active": active,
    })))
}

// ─── Trust Portal — admin handlers ─────────────────────────────────────────

async fn trust_upsert_document(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<DocumentInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let doc = state.trust.upsert_document(input).await.map_err(|e| {
        error!("trust upsert_document: {e}");
        err_json(StatusCode::BAD_REQUEST, "upsert failed")
    })?;
    Ok(created_json(doc))
}

async fn trust_list_documents_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let docs = state.trust.list_documents_admin().await.map_err(|e| {
        error!("trust list_documents_admin: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
    })?;
    Ok(ok_json(docs))
}

#[derive(Deserialize)]
struct SupersedeBody {
    new_id: String,
}

async fn trust_supersede_document(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((slug, version)): Path<(String, String)>,
    Json(body): Json<SupersedeBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    state
        .trust
        .supersede(&slug, &version, &body.new_id)
        .await
        .map_err(|e| {
            error!("trust supersede: {e}");
            err_json(StatusCode::BAD_REQUEST, "supersede failed")
        })?;
    Ok(ok_json(serde_json::json!({"superseded": true})))
}

async fn trust_upsert_subprocessor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<SubprocessorInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let s = state.trust.upsert_subprocessor(input).await.map_err(|e| {
        error!("trust upsert_subprocessor: {e}");
        err_json(StatusCode::BAD_REQUEST, "upsert failed")
    })?;
    Ok(created_json(s))
}

async fn trust_list_subprocessors_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let list = state.trust.list_subprocessors_admin().await.map_err(|e| {
        error!("trust list_subprocessors_admin: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
    })?;
    Ok(ok_json(list))
}

async fn trust_remove_subprocessor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    state.trust.remove_subprocessor(&name).await.map_err(|e| {
        error!("trust remove_subprocessor: {e}");
        err_json(StatusCode::BAD_REQUEST, "remove failed")
    })?;
    Ok(ok_json(serde_json::json!({"removed": true})))
}

async fn trust_create_incident(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<IncidentInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let incident = state.trust.create_incident(input).await.map_err(|e| {
        error!("trust create_incident: {e}");
        err_json(StatusCode::BAD_REQUEST, "create failed")
    })?;
    Ok(created_json(incident))
}

async fn trust_list_incidents_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<LimitQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let list = state.trust.list_incidents_admin(limit).await.map_err(|e| {
        error!("trust list_incidents_admin: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
    })?;
    Ok(ok_json(list))
}

#[derive(Deserialize)]
struct IncidentUpdateBody {
    status: String,
    body_md: String,
    posted_by: String,
}

async fn trust_post_incident_update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(incident_id): Path<String>,
    Json(b): Json<IncidentUpdateBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let upd = state
        .trust
        .post_incident_update(&incident_id, &b.status, &b.body_md, &b.posted_by)
        .await
        .map_err(|e| {
            error!("trust post_incident_update: {e}");
            err_json(StatusCode::BAD_REQUEST, "post failed")
        })?;
    Ok(created_json(upd))
}

async fn trust_list_incident_updates(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(incident_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let list = state
        .trust
        .list_incident_updates(&incident_id)
        .await
        .map_err(|e| {
            error!("trust list_incident_updates: {e}");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
        })?;
    Ok(ok_json(list))
}

async fn trust_list_access_requests(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let list = state
        .trust
        .list_access_requests_pending()
        .await
        .map_err(|e| {
            error!("trust list_access_requests_pending: {e}");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
        })?;
    Ok(ok_json(list))
}

#[derive(Deserialize)]
struct GrantBody {
    granted_by: String,
}

async fn trust_grant_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(b): Json<GrantBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    state
        .trust
        .grant_access_request(&request_id, &b.granted_by)
        .await
        .map_err(|e| {
            error!("trust grant_access: {e}");
            err_json(StatusCode::BAD_REQUEST, "grant failed")
        })?;
    Ok(ok_json(serde_json::json!({"granted": true})))
}

async fn trust_revoke_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    state
        .trust
        .revoke_access_request(&request_id)
        .await
        .map_err(|e| {
            error!("trust revoke_access: {e}");
            err_json(StatusCode::BAD_REQUEST, "revoke failed")
        })?;
    Ok(ok_json(serde_json::json!({"revoked": true})))
}

// ─── Trust Portal — questionnaire automation ─────────────────────────────

async fn trust_questionnaire_frameworks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    Ok(ok_json(framework_catalog()))
}

async fn trust_generate_questionnaire(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(framework): Path<String>,
    body: Option<Json<QuestionnaireGenerationRequest>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let framework = framework.parse::<QuestionnaireFramework>().map_err(|_| {
        err_json(
            StatusCode::BAD_REQUEST,
            "unsupported questionnaire framework",
        )
    })?;
    let request = body.map(|Json(body)| body).unwrap_or_default();
    let context = build_questionnaire_context(&state, &request).await?;
    let generated = generate_questionnaire(framework, request, context);
    Ok(ok_json(generated))
}

async fn trust_generate_security_review_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<QuestionnaireGenerationRequest>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let request = body.map(|Json(body)| body).unwrap_or_default();
    let context = build_questionnaire_context(&state, &request).await?;
    let report = generate_security_review_report(request, context);
    Ok(ok_json(report))
}

async fn build_questionnaire_context(
    state: &AppState,
    request: &QuestionnaireGenerationRequest,
) -> Result<QuestionnaireContext, (StatusCode, Json<serde_json::Value>)> {
    let mut controls = state.soc2.list_controls().await.map_err(|e| {
        error!("questionnaire list controls: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "control list failed")
    })?;
    if controls.is_empty() {
        state.soc2.seed_default_controls().await.map_err(|e| {
            error!("questionnaire seed controls: {e}");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "control seed failed")
        })?;
        controls = state.soc2.list_controls().await.map_err(|e| {
            error!("questionnaire relist controls: {e}");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "control list failed")
        })?;
    }

    let include_private = request.include_private_documents.unwrap_or(true);
    let documents = if include_private {
        state.trust.list_documents_admin().await
    } else {
        state.trust.list_documents_public().await
    }
    .map_err(|e| {
        error!("questionnaire list documents: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "document list failed")
    })?;

    let subprocessors = if include_private {
        state.trust.list_subprocessors_admin().await
    } else {
        state.trust.list_subprocessors_public().await
    }
    .map_err(|e| {
        error!("questionnaire list subprocessors: {e}");
        err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "subprocessor list failed",
        )
    })?;

    let incidents = if include_private {
        state.trust.list_incidents_admin(25).await
    } else {
        state.trust.list_incidents_public(25).await
    }
    .map_err(|e| {
        error!("questionnaire list incidents: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "incident list failed")
    })?;

    let hipaa_baa_active = match request.tenant_id.as_deref() {
        Some(tenant_id) => state.hipaa.is_active_for_tenant(tenant_id).await,
        None => false,
    };

    Ok(QuestionnaireContext {
        tenant_id: request.tenant_id.clone(),
        controls,
        documents,
        subprocessors,
        incidents,
        hipaa_baa_active,
        generated_at: Utc::now(),
    })
}

// ─── Trust Portal — public handlers (no auth) ──────────────────────────────

async fn public_trust_overview(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let o = state.trust.overview().await.map_err(|e| {
        error!("trust overview: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "overview failed")
    })?;
    Ok(ok_json(o))
}

async fn public_trust_documents(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let docs = state.trust.list_documents_public().await.map_err(|e| {
        error!("trust list_documents_public: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
    })?;
    Ok(ok_json(docs))
}

async fn public_trust_document_by_slug(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    match state.trust.get_document_by_slug(&slug, None).await {
        Ok(Some(d)) if d.public && d.published_at.is_some() => Ok(ok_json(d)),
        Ok(_) => Err(err_json(StatusCode::NOT_FOUND, "not found")),
        Err(e) => {
            error!("trust get_document_by_slug: {e}");
            Err(err_json(StatusCode::INTERNAL_SERVER_ERROR, "fetch failed"))
        }
    }
}

async fn public_trust_subprocessors(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let list = state.trust.list_subprocessors_public().await.map_err(|e| {
        error!("trust list_subprocessors_public: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
    })?;
    Ok(ok_json(list))
}

async fn public_trust_incidents(
    State(state): State<Arc<AppState>>,
    Query(q): Query<LimitQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let list = state
        .trust
        .list_incidents_public(limit)
        .await
        .map_err(|e| {
            error!("trust list_incidents_public: {e}");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "list failed")
        })?;
    Ok(ok_json(list))
}

async fn public_trust_access_request(
    State(state): State<Arc<AppState>>,
    Json(input): Json<AccessRequestInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let req = state
        .trust
        .submit_access_request(input)
        .await
        .map_err(|e| {
            error!("trust submit_access_request: {e}");
            err_json(StatusCode::BAD_REQUEST, "submit failed")
        })?;
    Ok(created_json(req))
}

// ─── DB-backed admin/public handler tests ───────────────────────────────────
//
// Every admin route is gated by the service Bearer token; the public trust
// routes are anonymous but must expose only public rows. User error is 4xx.

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::test_support;
    use serde_json::json;
    use uuid::Uuid;

    const TOKEN: &str = "unit-admin-service-token";

    async fn state(suffix: &str) -> Option<Arc<AppState>> {
        let pool =
            test_support::canonical_pool(&format!("admin_{suffix}"), &format!("admin_{suffix}"))
                .await?;
        Some(test_support::app_state(pool, TOKEN))
    }

    fn auth() -> HeaderMap {
        test_support::bearer(TOKEN)
    }

    fn status<R: IntoResponse>(r: Result<R, (StatusCode, Json<serde_json::Value>)>) -> StatusCode {
        match r {
            Ok(response) => response.into_response().status(),
            Err((code, _)) => code,
        }
    }

    fn error_of<R: IntoResponse>(
        r: Result<R, (StatusCode, Json<serde_json::Value>)>,
    ) -> (StatusCode, serde_json::Value) {
        match r {
            Ok(_) => panic!("expected an error response"),
            Err((code, body)) => (code, body.0),
        }
    }

    async fn json_data<R: IntoResponse>(
        r: Result<R, (StatusCode, Json<serde_json::Value>)>,
    ) -> serde_json::Value {
        match r {
            Ok(response) => {
                let bytes = axum::body::to_bytes(response.into_response().into_body(), 1 << 22)
                    .await
                    .expect("body");
                let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
                value["data"].clone()
            }
            Err((code, body)) => panic!("expected success, got {code}: {}", body.0),
        }
    }

    fn document_input(slug: &str) -> DocumentInput {
        DocumentInput {
            slug: slug.into(),
            title: "Security Whitepaper".into(),
            document_type: "whitepaper".into(),
            version: "v1".into(),
            summary: Some("summary".into()),
            content_md: "# SECURITY\nAll good.".into(),
            storage_url: None,
            public: true,
            requires_nda: false,
            publish_now: true,
        }
    }

    fn subprocessor_input(name: &str) -> SubprocessorInput {
        SubprocessorInput {
            name: name.into(),
            purpose: "delivery".into(),
            location: "EE".into(),
            data_categories: vec!["email".into()],
            dpa_url: None,
            certifications: vec!["ISO 27001".into()],
            public: true,
        }
    }

    fn incident_input(slug: &str) -> IncidentInput {
        IncidentInput {
            slug: slug.into(),
            title: "Degradation".into(),
            severity: "medium".into(),
            status: "investigating".into(),
            started_at: Utc::now(),
            summary_md: "We are on it.".into(),
            impact: None,
            customer_data_affected: false,
            public: true,
        }
    }

    fn baa_sign_input() -> SignBaaInput {
        SignBaaInput {
            signer_name: "Alice".into(),
            signer_email: "alice@example.test".into(),
            signer_title: Some("CTO".into()),
            signer_ip: Some("203.0.113.5".into()),
            document_url: None,
            document_sha256: Some("a".repeat(64)),
        }
    }

    fn baa_countersign_input() -> CountersignBaaInput {
        CountersignBaaInput {
            countersigner_name: "ApexMail Legal".into(),
            countersigner_email: "legal@apexmail.ee".into(),
            effective_date: None,
        }
    }

    #[tokio::test]
    async fn every_admin_handler_refuses_a_missing_token() {
        let Some(state) = state("authgate").await else {
            return;
        };
        let none = HeaderMap::new();
        let q: Query<LimitQuery> = Query(LimitQuery { limit: Some(10) });
        let list_q: Query<ListBaaQuery> = Query(ListBaaQuery { tenant_id: None });

        let codes = vec![
            status(soc2_seed_controls(State(state.clone()), none.clone()).await),
            status(soc2_list_controls(State(state.clone()), none.clone()).await),
            status(soc2_get_control(State(state.clone()), none.clone(), Path("AC-1".into())).await),
            status(
                soc2_update_status(
                    State(state.clone()),
                    none.clone(),
                    Path("AC-1".into()),
                    Json(UpdateStatusBody {
                        status: "in_scope".into(),
                    }),
                )
                .await,
            ),
            status(
                soc2_list_evidence(
                    State(state.clone()),
                    none.clone(),
                    Path("AC-1".into()),
                    Query(EvidenceQuery { limit: None }),
                )
                .await,
            ),
            status(
                soc2_run_collectors(
                    State(state.clone()),
                    none.clone(),
                    Some(Json(RunBody::default())),
                )
                .await,
            ),
            status(
                hipaa_request_baa(
                    State(state.clone()),
                    none.clone(),
                    Json(RequestBaaBody {
                        tenant_id: "t".into(),
                        version: "v1".into(),
                        actor: "a".into(),
                    }),
                )
                .await,
            ),
            status(hipaa_list_baas(State(state.clone()), none.clone(), list_q).await),
            status(hipaa_get_baa(State(state.clone()), none.clone(), Path("b".into())).await),
            status(
                hipaa_sign(
                    State(state.clone()),
                    none.clone(),
                    Path("b".into()),
                    Json(SignBody {
                        actor: "a".into(),
                        input: baa_sign_input(),
                    }),
                )
                .await,
            ),
            status(
                hipaa_countersign(
                    State(state.clone()),
                    none.clone(),
                    Path("b".into()),
                    Json(CountersignBody {
                        actor: "a".into(),
                        input: baa_countersign_input(),
                    }),
                )
                .await,
            ),
            status(
                hipaa_activate(
                    State(state.clone()),
                    none.clone(),
                    Path("b".into()),
                    Json(ActorBody { actor: "a".into() }),
                )
                .await,
            ),
            status(
                hipaa_terminate(
                    State(state.clone()),
                    none.clone(),
                    Path("b".into()),
                    Json(TerminateBody {
                        actor: "a".into(),
                        reason: "done".into(),
                    }),
                )
                .await,
            ),
            status(
                hipaa_active_for_tenant(State(state.clone()), none.clone(), Path("t".into())).await,
            ),
            status(
                trust_upsert_document(
                    State(state.clone()),
                    none.clone(),
                    Json(document_input("s")),
                )
                .await,
            ),
            status(trust_list_documents_admin(State(state.clone()), none.clone()).await),
            status(
                trust_supersede_document(
                    State(state.clone()),
                    none.clone(),
                    Path(("s".into(), "v1".into())),
                    Json(SupersedeBody { new_id: "n".into() }),
                )
                .await,
            ),
            status(
                trust_upsert_subprocessor(
                    State(state.clone()),
                    none.clone(),
                    Json(subprocessor_input("p")),
                )
                .await,
            ),
            status(trust_list_subprocessors_admin(State(state.clone()), none.clone()).await),
            status(
                trust_remove_subprocessor(State(state.clone()), none.clone(), Path("p".into()))
                    .await,
            ),
            status(
                trust_create_incident(
                    State(state.clone()),
                    none.clone(),
                    Json(incident_input("i")),
                )
                .await,
            ),
            status(trust_list_incidents_admin(State(state.clone()), none.clone(), q).await),
            status(
                trust_post_incident_update(
                    State(state.clone()),
                    none.clone(),
                    Path("i".into()),
                    Json(IncidentUpdateBody {
                        status: "monitoring".into(),
                        body_md: "b".into(),
                        posted_by: "a".into(),
                    }),
                )
                .await,
            ),
            status(
                trust_list_incident_updates(State(state.clone()), none.clone(), Path("i".into()))
                    .await,
            ),
            status(trust_list_access_requests(State(state.clone()), none.clone()).await),
            status(
                trust_grant_access(
                    State(state.clone()),
                    none.clone(),
                    Path("r".into()),
                    Json(GrantBody {
                        granted_by: "a".into(),
                    }),
                )
                .await,
            ),
            status(trust_revoke_access(State(state.clone()), none.clone(), Path("r".into())).await),
            status(trust_questionnaire_frameworks(State(state.clone()), none.clone()).await),
            status(
                trust_generate_questionnaire(
                    State(state.clone()),
                    none.clone(),
                    Path("sig".into()),
                    Some(Json(QuestionnaireGenerationRequest::default())),
                )
                .await,
            ),
            status(
                trust_generate_security_review_report(
                    State(state.clone()),
                    none.clone(),
                    Some(Json(QuestionnaireGenerationRequest::default())),
                )
                .await,
            ),
        ];
        assert_eq!(codes.len(), 30, "every admin handler is listed");
        for (index, code) in codes.iter().enumerate() {
            assert_eq!(*code, StatusCode::UNAUTHORIZED, "admin handler #{index}");
        }
    }

    #[tokio::test]
    async fn soc2_handlers_seed_list_get_and_validate_status() {
        let Some(state) = state("soc2").await else {
            return;
        };
        let seeded = json_data(soc2_seed_controls(State(state.clone()), auth()).await).await;
        assert_eq!(seeded["seeded"], json!(true));
        let controls = json_data(soc2_list_controls(State(state.clone()), auth()).await).await;
        let controls = controls.as_array().expect("controls").clone();
        assert!(!controls.is_empty());
        let control_id = controls[0]["control_id"]
            .as_str()
            .expect("control id")
            .to_string();

        // Unknown control id is a 404.
        assert_eq!(
            status(soc2_get_control(State(state.clone()), auth(), Path("NO-SUCH".into())).await),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(soc2_get_control(State(state.clone()), auth(), Path(control_id.clone())).await),
            StatusCode::OK
        );

        // Unknown status string is a 400 and changes nothing.
        let (code, body) = error_of(
            soc2_update_status(
                State(state.clone()),
                auth(),
                Path(control_id.clone()),
                Json(UpdateStatusBody {
                    status: "certified".into(),
                }),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("certified"));
        assert_eq!(
            status(
                soc2_update_status(
                    State(state.clone()),
                    auth(),
                    Path(control_id.clone()),
                    Json(UpdateStatusBody {
                        status: "deferred".into(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                soc2_list_evidence(
                    State(state.clone()),
                    auth(),
                    Path(control_id.clone()),
                    Query(EvidenceQuery { limit: Some(-5) }),
                )
                .await
            ),
            StatusCode::OK,
            "the limit is clamped, a negative value is not an error"
        );
        assert_eq!(
            status(soc2_run_collectors(State(state.clone()), auth(), None).await),
            StatusCode::OK
        );
        assert_eq!(
            status(
                soc2_run_collectors(
                    State(state.clone()),
                    auth(),
                    Some(Json(RunBody {
                        period_start: Some(Utc::now() - Duration::days(2)),
                        period_end: Some(Utc::now()),
                    })),
                )
                .await
            ),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn hipaa_admin_handlers_drive_the_baa_lifecycle() {
        let Some(state) = state("hipaa").await else {
            return;
        };
        let tenant = test_support::unique_tenant();

        // Both list filters are required.
        let (code, _) = error_of(
            hipaa_list_baas(
                State(state.clone()),
                auth(),
                Query(ListBaaQuery { tenant_id: None }),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);

        let baa = json_data(
            hipaa_request_baa(
                State(state.clone()),
                auth(),
                Json(RequestBaaBody {
                    tenant_id: tenant.clone(),
                    version: "v3.0".into(),
                    actor: "admin@apexmail.ee".into(),
                }),
            )
            .await,
        )
        .await;
        let baa_id = baa["id"].as_str().expect("baa id").to_string();
        assert_eq!(
            status(hipaa_get_baa(State(state.clone()), auth(), Path(baa_id.clone())).await),
            StatusCode::OK
        );
        assert_eq!(
            status(hipaa_get_baa(State(state.clone()), auth(), Path("nope".into())).await),
            StatusCode::NOT_FOUND
        );
        let listed = json_data(
            hipaa_list_baas(
                State(state.clone()),
                auth(),
                Query(ListBaaQuery {
                    tenant_id: Some(tenant.clone()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(listed.as_array().expect("list").len(), 1);

        // Out-of-order activation is a 400, not an internal error.
        let (code, _) = error_of(
            hipaa_activate(
                State(state.clone()),
                auth(),
                Path(baa_id.clone()),
                Json(ActorBody {
                    actor: "admin@apexmail.ee".into(),
                }),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);

        assert_eq!(
            status(
                hipaa_sign(
                    State(state.clone()),
                    auth(),
                    Path(baa_id.clone()),
                    Json(SignBody {
                        actor: "admin@apexmail.ee".into(),
                        input: baa_sign_input(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                hipaa_countersign(
                    State(state.clone()),
                    auth(),
                    Path(baa_id.clone()),
                    Json(CountersignBody {
                        actor: "admin@apexmail.ee".into(),
                        input: baa_countersign_input(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                hipaa_activate(
                    State(state.clone()),
                    auth(),
                    Path(baa_id.clone()),
                    Json(ActorBody {
                        actor: "admin@apexmail.ee".into(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        let active = json_data(
            hipaa_active_for_tenant(State(state.clone()), auth(), Path(tenant.clone())).await,
        )
        .await;
        assert_eq!(active["active"], json!(true));
        assert_eq!(active["tenant_id"], json!(tenant));
        // Tenant isolation: an unrelated tenant is inactive.
        let other = json_data(
            hipaa_active_for_tenant(
                State(state.clone()),
                auth(),
                Path(test_support::unique_tenant()),
            )
            .await,
        )
        .await;
        assert_eq!(other["active"], json!(false));

        // Terminating without a reason is refused by the state machine.
        assert_eq!(
            status(
                hipaa_terminate(
                    State(state.clone()),
                    auth(),
                    Path(baa_id.clone()),
                    Json(TerminateBody {
                        actor: "admin@apexmail.ee".into(),
                        reason: "  ".into(),
                    }),
                )
                .await
            ),
            StatusCode::BAD_REQUEST,
            "an empty termination reason must be refused by the store"
        );
        assert_eq!(
            status(
                hipaa_terminate(
                    State(state.clone()),
                    auth(),
                    Path(baa_id.clone()),
                    Json(TerminateBody {
                        actor: "admin@apexmail.ee".into(),
                        reason: "contract ended".into(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn trust_admin_handlers_crud_and_public_visibility() {
        let Some(state) = state("trust").await else {
            return;
        };
        let suffix = &Uuid::new_v4().simple().to_string()[..8];
        let slug = format!("whitepaper-{suffix}");
        let name = format!("Processor {suffix}");
        let incident_slug = format!("incident-{suffix}");

        let doc = json_data(
            trust_upsert_document(State(state.clone()), auth(), Json(document_input(&slug))).await,
        )
        .await;
        let doc_id = doc["id"].as_str().expect("doc id").to_string();
        assert_eq!(
            status(trust_list_documents_admin(State(state.clone()), auth()).await),
            StatusCode::OK
        );
        let mut v2_input = document_input(&slug);
        v2_input.version = "v2".into();
        v2_input.content_md = "# SECURITY v2".into();
        let v2 =
            json_data(trust_upsert_document(State(state.clone()), auth(), Json(v2_input)).await)
                .await;
        let v2_id = v2["id"].as_str().expect("v2 id").to_string();
        assert_ne!(v2_id, doc_id);
        assert_eq!(
            status(
                trust_supersede_document(
                    State(state.clone()),
                    auth(),
                    Path((slug.clone(), "v1".into())),
                    Json(SupersedeBody {
                        new_id: v2_id.clone(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );

        let processor = json_data(
            trust_upsert_subprocessor(
                State(state.clone()),
                auth(),
                Json(subprocessor_input(&name)),
            )
            .await,
        )
        .await;
        assert_eq!(processor["name"], json!(name));
        assert_eq!(
            status(trust_list_subprocessors_admin(State(state.clone()), auth()).await),
            StatusCode::OK
        );
        assert_eq!(
            status(
                trust_remove_subprocessor(State(state.clone()), auth(), Path(name.clone())).await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                trust_remove_subprocessor(State(state.clone()), auth(), Path(name.clone())).await
            ),
            StatusCode::OK,
            "removal is idempotent"
        );

        // Incidents: an invalid severity is refused before any write.
        let mut bad = incident_input(&incident_slug);
        bad.severity = "apocalyptic".into();
        let (code, _) =
            error_of(trust_create_incident(State(state.clone()), auth(), Json(bad)).await);
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let incident = json_data(
            trust_create_incident(
                State(state.clone()),
                auth(),
                Json(incident_input(&incident_slug)),
            )
            .await,
        )
        .await;
        let incident_id = incident["id"].as_str().expect("incident id").to_string();
        assert_eq!(
            status(
                trust_list_incidents_admin(
                    State(state.clone()),
                    auth(),
                    Query(LimitQuery { limit: Some(0) }),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                trust_post_incident_update(
                    State(state.clone()),
                    auth(),
                    Path(incident_id.clone()),
                    Json(IncidentUpdateBody {
                        status: "investigating".into(),
                        body_md: "update".into(),
                        posted_by: "oncall".into(),
                    }),
                )
                .await
            ),
            StatusCode::CREATED
        );
        let updates = json_data(
            trust_list_incident_updates(State(state.clone()), auth(), Path(incident_id.clone()))
                .await,
        )
        .await;
        assert_eq!(updates.as_array().expect("updates").len(), 1);
        // An invalid update status is refused and nothing is appended.
        assert_eq!(
            status(
                trust_post_incident_update(
                    State(state.clone()),
                    auth(),
                    Path(incident_id.clone()),
                    Json(IncidentUpdateBody {
                        status: "finished".into(),
                        body_md: "x".into(),
                        posted_by: "oncall".into(),
                    }),
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
        let updates = json_data(
            trust_list_incident_updates(State(state.clone()), auth(), Path(incident_id.clone()))
                .await,
        )
        .await;
        assert_eq!(updates.as_array().expect("updates").len(), 1);

        // Public views expose only public rows; the public document lookup
        // requires a published, public version.
        assert_eq!(
            status(public_trust_overview(State(state.clone())).await),
            StatusCode::OK
        );
        assert_eq!(
            status(public_trust_documents(State(state.clone())).await),
            StatusCode::OK
        );
        let public_doc = json_data(
            public_trust_document_by_slug(State(state.clone()), Path(slug.clone())).await,
        )
        .await;
        assert_eq!(public_doc["slug"], json!(slug));
        assert_eq!(
            status(
                public_trust_document_by_slug(State(state.clone()), Path("missing".into())).await
            ),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(public_trust_subprocessors(State(state.clone())).await),
            StatusCode::OK
        );
        assert_eq!(
            status(
                public_trust_incidents(
                    State(state.clone()),
                    Query(LimitQuery { limit: Some(-1) }),
                )
                .await
            ),
            StatusCode::OK,
            "the public incident limit is clamped"
        );

        // Anonymous access requests: malformed email refused, valid one stored.
        assert_eq!(
            status(
                public_trust_access_request(
                    State(state.clone()),
                    Json(AccessRequestInput {
                        document_slug: slug.clone(),
                        requester_name: "Mallory".into(),
                        requester_email: "nope".into(),
                        company: None,
                        purpose: None,
                        nda_accepted: false,
                    }),
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(
                public_trust_access_request(
                    State(state.clone()),
                    Json(AccessRequestInput {
                        document_slug: slug.clone(),
                        requester_name: "Alice".into(),
                        requester_email: "alice@example.test".into(),
                        company: Some("Acme".into()),
                        purpose: Some("review".into()),
                        nda_accepted: true,
                    }),
                )
                .await
            ),
            StatusCode::CREATED
        );
        let requests =
            json_data(trust_list_access_requests(State(state.clone()), auth()).await).await;
        let request_id = requests[0]["id"].as_str().expect("request id").to_string();
        assert_eq!(
            status(
                trust_grant_access(
                    State(state.clone()),
                    auth(),
                    Path(request_id.clone()),
                    Json(GrantBody {
                        granted_by: "admin@apexmail.ee".into(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        // Granting a request that no longer exists is reported, never faked.
        assert_eq!(
            status(
                trust_grant_access(
                    State(state.clone()),
                    auth(),
                    Path("no-such-request".into()),
                    Json(GrantBody {
                        granted_by: "admin@apexmail.ee".into(),
                    }),
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(
                trust_revoke_access(State(state.clone()), auth(), Path(request_id.clone())).await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                trust_revoke_access(State(state.clone()), auth(), Path("no-such-request".into()))
                    .await
            ),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn questionnaire_endpoints_validate_frameworks_and_never_leak_private_docs() {
        let Some(state) = state("questionnaire").await else {
            return;
        };
        let frameworks =
            json_data(trust_questionnaire_frameworks(State(state.clone()), auth()).await).await;
        assert!(frameworks.as_array().expect("frameworks").len() >= 3);

        // Unknown framework is a 400.
        let (code, _) = error_of(
            trust_generate_questionnaire(
                State(state.clone()),
                auth(),
                Path("nonsense".into()),
                None,
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);

        // A private document must not reach a public-only questionnaire.
        let private_slug = format!("private-{}", &Uuid::new_v4().simple().to_string()[..8]);
        let mut private = document_input(&private_slug);
        private.public = false;
        private.content_md = "TOP SECRET ROADMAP".into();
        json_data(trust_upsert_document(State(state.clone()), auth(), Json(private)).await).await;

        for framework in ["sig", "CCM", "hecvat"] {
            assert_eq!(
                status(
                    trust_generate_questionnaire(
                        State(state.clone()),
                        auth(),
                        Path(framework.into()),
                        Some(Json(QuestionnaireGenerationRequest {
                            include_private_documents: Some(false),
                            ..Default::default()
                        })),
                    )
                    .await
                ),
                StatusCode::OK,
                "framework {framework}"
            );
        }
        let public_report = json_data(
            trust_generate_questionnaire(
                State(state.clone()),
                auth(),
                Path("sig".into()),
                Some(Json(QuestionnaireGenerationRequest {
                    include_private_documents: Some(false),
                    include_markdown_report: Some(true),
                    ..Default::default()
                })),
            )
            .await,
        )
        .await;
        let serialized = serde_json::to_string(&public_report).expect("serialize");
        assert!(
            !serialized.contains("TOP SECRET ROADMAP"),
            "a public questionnaire must not disclose private documents"
        );

        assert_eq!(
            status(
                trust_generate_security_review_report(
                    State(state.clone()),
                    auth(),
                    Some(Json(QuestionnaireGenerationRequest {
                        requester_company: Some("Acme".into()),
                        ..Default::default()
                    })),
                )
                .await
            ),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn trust_supersede_and_remove_are_not_vulnerable_to_unknown_targets() {
        let Some(state) = state("unknown").await else {
            return;
        };
        // Superseding an unknown document is a no-op in the store; the row
        // count is unchanged, which the handler reports honestly.
        assert_eq!(
            status(
                trust_supersede_document(
                    State(state.clone()),
                    auth(),
                    Path(("missing".into(), "v9".into())),
                    Json(SupersedeBody { new_id: "n".into() }),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                trust_remove_subprocessor(State(state.clone()), auth(), Path("ghost".into())).await
            ),
            StatusCode::OK
        );
        // And the public overview never panics on an empty portal.
        let overview = json_data(public_trust_overview(State(state.clone())).await).await;
        assert!(overview["published_documents"]
            .as_array()
            .expect("documents")
            .is_empty());
    }
}
