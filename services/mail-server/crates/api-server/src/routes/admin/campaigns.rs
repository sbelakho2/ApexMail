//! Drip campaign listing endpoint.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_campaigns))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignRow {
    pub id: String,
    pub name: String,
    pub status: String,
    pub description: Option<String>,
    pub from_email: Option<String>,
    pub from_name: Option<String>,
    pub sequence: serde_json::Value,
    pub stats: serde_json::Value,
    pub created_at: String,
    pub started_at: Option<String>,
}

async fn list_campaigns(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<CampaignsQuery>,
) -> Result<Json<Vec<CampaignRow>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&auth)?;

    // Check table exists
    let exists: Option<(bool,)> = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relname = 'drip_campaigns')",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    if !exists.map(|r| r.0).unwrap_or(false) {
        return Ok(Json(vec![]));
    }

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            serde_json::Value,
            serde_json::Value,
            chrono::DateTime<chrono::Utc>,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(
        "SELECT id::text, name, status, description, from_email, from_name,
                COALESCE(sequence, '[]'::jsonb), COALESCE(stats, '{}'::jsonb),
                created_at, started_at
         FROM drip_campaigns ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let campaigns: Vec<CampaignRow> = rows
        .into_iter()
        .map(
            |(id, name, status, desc, fe, fn_, seq, stats, ca, sa)| CampaignRow {
                id,
                name,
                status,
                description: desc,
                from_email: fe,
                from_name: fn_,
                sequence: seq,
                stats,
                created_at: ca.to_rfc3339(),
                started_at: sa.map(|t| t.to_rfc3339()),
            },
        )
        .collect();

    Ok(Json(campaigns))
}
