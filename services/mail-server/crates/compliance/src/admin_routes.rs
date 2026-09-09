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
