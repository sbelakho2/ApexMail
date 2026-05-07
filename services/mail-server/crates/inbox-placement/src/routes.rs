//! Axum route handlers for the Inbox Placement API.
//!
//! These handlers are transport-agnostic and receive already-extracted auth
//! context parameters. The api-server crate wraps them with auth middleware.

use axum::http::StatusCode;
use axum::Json;
use std::sync::Arc;
use uuid::Uuid;

use crate::engine::PlacementEngine;
use crate::types::*;

/// Shared state for inbox-placement route handlers.
pub struct PlacementState {
    pub engine: Arc<PlacementEngine>,
    pub db: sqlx::PgPool,
}

// ── Helper: error JSON tuple ──────────────────────────────────

fn err(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({
            "error": msg
        })),
    )
}

fn ok(data: serde_json::Value) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(data))
}

fn created(data: serde_json::Value) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::CREATED, Json(data))
}

// ── Handlers ──────────────────────────────────────────────────

/// `POST /v1/inbox-placement/tests` — create a new placement test.
pub async fn create_placement_test(
    state: Arc<PlacementState>,
    tenant_id: String,
    body: CreateTestRequest,
) -> (StatusCode, Json<serde_json::Value>) {
    let tenant_uuid = match Uuid::parse_str(&tenant_id) {
        Ok(id) => id,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid tenant_id"),
    };

    match state.engine.create_test(body, tenant_uuid).await {
        Ok(test) => created(serde_json::json!(test)),
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

/// `GET /v1/inbox-placement/tests` — list placement tests (paginated).
pub async fn list_placement_tests(
    state: Arc<PlacementState>,
    tenant_id: String,
    page: Option<u32>,
    per_page: Option<u32>,
    status: Option<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tenant_uuid = match Uuid::parse_str(&tenant_id) {
        Ok(id) => id,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid tenant_id"),
    };

    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).clamp(1, 100);
    let limit = per_page as i64;
    let offset = ((page - 1) as i64) * limit;

    // Count total matching tests for pagination metadata.
    let count_query = if let Some(ref status_filter) = status {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM placement_tests WHERE tenant_id = $1 AND status = $2",
        )
        .bind(tenant_uuid)
        .bind(status_filter)
        .fetch_one(&state.db)
        .await
    } else {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM placement_tests WHERE tenant_id = $1",
        )
        .bind(tenant_uuid)
        .fetch_one(&state.db)
        .await
    };

    let total = match count_query {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "inbox-placement: count query failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let rows_query = if let Some(ref status_filter) = status {
        sqlx::query_as::<_, PlacementTest>(
            r#"SELECT id, tenant_id, name, status, from_email, subject,
                      total_accounts, completed_accounts, seed_accounts_used,
                      scheduled_for, completed_at, created_at
               FROM placement_tests
               WHERE tenant_id = $1 AND status = $2
               ORDER BY created_at DESC
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_uuid)
        .bind(status_filter)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, PlacementTest>(
            r#"SELECT id, tenant_id, name, status, from_email, subject,
                      total_accounts, completed_accounts, seed_accounts_used,
                      scheduled_for, completed_at, created_at
               FROM placement_tests
               WHERE tenant_id = $1
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_uuid)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
    };

    let tests = match rows_query {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "inbox-placement: list query failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let items: Vec<serde_json::Value> = tests
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "status": t.status,
                "from_email": t.from_email,
                "subject": t.subject,
                "total_accounts": t.total_accounts,
                "completed_accounts": t.completed_accounts,
                "created_at": t.created_at,
            })
        })
        .collect();

    ok(serde_json::json!({
        "tests": items,
        "total": total,
        "page": page,
        "per_page": per_page,
    }))
}

/// `GET /v1/inbox-placement/tests/:id` — get test details + results + score.
pub async fn get_placement_test(
    state: Arc<PlacementState>,
    tenant_id: String,
    id: Uuid,
) -> (StatusCode, Json<serde_json::Value>) {
    let tenant_uuid = match Uuid::parse_str(&tenant_id) {
        Ok(id) => id,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid tenant_id"),
    };

    // Load the test itself.
    let test = match sqlx::query_as::<_, PlacementTest>(
        r#"SELECT id, tenant_id, name, status, from_email, subject,
                  total_accounts, completed_accounts, seed_accounts_used,
                  scheduled_for, completed_at, created_at
           FROM placement_tests
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(tenant_uuid)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(t)) => t,
        Ok(None) => return err(StatusCode::NOT_FOUND, "placement test not found"),
        Err(e) => {
            tracing::error!(error = %e, "inbox-placement: get test query failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    // Get results and score.
    let results = match state.engine.get_test_results(id, tenant_uuid).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "inbox-placement: get results failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "failed to get results");
        }
    };

    let score = match state.engine.get_placement_score(id, tenant_uuid).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "inbox-placement: get score failed");
            None
        }
    };

    // Build summary from results.
    let total_accounts = results.iter().map(|r| r.accounts_tested).sum::<i32>();
    let summary = if total_accounts > 0 {
        let inbox_pct = results.iter().map(|r| r.inbox).sum::<i32>() as f64 / total_accounts as f64 * 100.0;
        let promotions_pct = results.iter().map(|r| r.promotions).sum::<i32>() as f64 / total_accounts as f64 * 100.0;
        let spam_pct = results.iter().map(|r| r.spam).sum::<i32>() as f64 / total_accounts as f64 * 100.0;
        let absent_pct = results.iter().map(|r| r.absent).sum::<i32>() as f64 / total_accounts as f64 * 100.0;
        Some(serde_json::json!({
            "inbox_pct": (inbox_pct * 100.0).round() / 100.0,
            "promotions_pct": (promotions_pct * 100.0).round() / 100.0,
            "spam_pct": (spam_pct * 100.0).round() / 100.0,
            "absent_pct": (absent_pct * 100.0).round() / 100.0,
        }))
    } else {
        None
    };

    ok(serde_json::json!({
        "id": test.id,
        "name": test.name,
        "status": test.status,
        "from_email": test.from_email,
        "subject": test.subject,
        "total_accounts": test.total_accounts,
        "completed_accounts": test.completed_accounts,
        "summary": summary,
        "overall_score": score.as_ref().map(|s| s.overall),
        "score": score,
        "results": results,
        "created_at": test.created_at,
    }))
}

/// `GET /v1/inbox-placement/trends` — get placement trends.
pub async fn get_placement_trends(
    state: Arc<PlacementState>,
    tenant_id: String,
    days: Option<u32>,
    provider: Option<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tenant_uuid = match Uuid::parse_str(&tenant_id) {
        Ok(id) => id,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid tenant_id"),
    };

    let days = days.unwrap_or(30) as i32;

    // Parse optional provider filter.
    let provider = provider
        .as_deref()
        .map(ProviderName::from_str);

    match state.engine.get_trends(tenant_uuid, days, provider).await {
        Ok(trends) => ok(serde_json::json!({ "trends": trends })),
        Err(e) => {
            tracing::error!(error = %e, "inbox-placement: get trends failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "failed to get trends")
        }
    }
}

/// `GET /v1/inbox-placement/providers` — list seed providers with active account counts.
pub async fn list_seed_providers(
    state: Arc<PlacementState>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.engine.seed_manager.list_providers().await {
        Ok(providers) => ok(serde_json::json!({ "providers": providers })),
        Err(e) => {
            tracing::error!(error = %e, "inbox-placement: list providers failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "failed to list providers")
        }
    }
}
