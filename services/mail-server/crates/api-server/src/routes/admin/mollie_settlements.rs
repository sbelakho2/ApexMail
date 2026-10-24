//! Operator settlement surface.
//!
//! Mollie pays merchants out in settlements. The billing client reads them
//! (`GET /v2/settlements`, `GET /v2/settlements/{id}`) and this router exposes
//! them to the control plane so payout reconciliation uses the provider's own
//! objects instead of a re-derived guess. Settlements never grant customer
//! entitlement: entitlement follows the paid invoice/subscription facts.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};

use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_settlements))
        .route("/:id", get(get_settlement))
}

fn client() -> Result<billing_service::mollie_client::MollieClient, Response> {
    billing_service::mollie_client::MollieClient::from_env().map_err(|error| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "code": "SERVICE_UNAVAILABLE",
                    "message": format!("Mollie is not configured: {error}"),
                }
            })),
        )
            .into_response()
    })
}

async fn list_settlements(
    State(_state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, Response> {
    crate::middleware::auth::require_scopes(&auth, &["*"]).map_err(IntoResponse::into_response)?;
    let client = client()?;
    let settlements = client.list_settlements(None).await.map_err(|error| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": {
                    "code": "PROVIDER_ERROR",
                    "message": format!("Mollie settlements could not be read: {error}"),
                }
            })),
        )
            .into_response()
    })?;
    Ok(Json(serde_json::json!({
        "settlements": settlements.iter().map(settlement_json).collect::<Vec<_>>(),
    })))
}

async fn get_settlement(
    State(_state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    crate::middleware::auth::require_scopes(&auth, &["*"]).map_err(IntoResponse::into_response)?;
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || !id.starts_with("stl_") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {"code": "BAD_REQUEST", "message": "not a Mollie settlement id"},
            })),
        )
            .into_response());
    }
    let client = client()?;
    let settlement = client.get_settlement(&id).await.map_err(|error| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": {
                    "code": "PROVIDER_ERROR",
                    "message": format!("Mollie settlement {id} could not be read: {error}"),
                }
            })),
        )
            .into_response()
    })?;
    Ok(Json(settlement_json(&settlement)))
}

fn settlement_json(settlement: &billing_service::mollie_client::Settlement) -> serde_json::Value {
    serde_json::json!({
        "id": settlement.id,
        "status": settlement.status,
        "amountCents": settlement.amount.as_ref().map(|money| money.cents),
        "currency": settlement.amount.as_ref().map(|money| money.currency.clone()),
        "settledAt": settlement.settled_at,
    })
}
