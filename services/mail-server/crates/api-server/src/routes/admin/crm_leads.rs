//! CRM leads listing endpoint.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_crm_leads))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrmLeadsQuery {
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
pub struct CrmLead {
    pub id: String,
    pub company_name: Option<String>,
    pub domain: Option<String>,
    pub contact_email: Option<String>,
    pub contact_name: Option<String>,
    pub stage: Option<String>,
    pub score: Option<i32>,
    pub source: Option<String>,
    pub last_activity: Option<String>,
    pub created_at: String,
    pub tags: serde_json::Value,
}

async fn list_crm_leads(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<CrmLeadsQuery>,
) -> Result<Json<Vec<CrmLead>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    // Check table exists
    let exists: Option<(bool,)> = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relname = 'sales_leads')",
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
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<i32>,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            chrono::DateTime<chrono::Utc>,
            serde_json::Value,
        ),
    >(
        "SELECT id::text, company_name, domain, contact_email, contact_name,
                stage, score, source, last_activity, created_at,
                COALESCE(tags, '[]'::jsonb)
         FROM sales_leads ORDER BY score DESC NULLS LAST, created_at DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let leads: Vec<CrmLead> = rows
        .into_iter()
        .map(
            |(id, cn, dom, ce, cname, stage, score, src, la, ca, tags)| CrmLead {
                id,
                company_name: cn,
                domain: dom,
                contact_email: ce,
                contact_name: cname,
                stage,
                score,
                source: src,
                last_activity: la.map(|t| t.to_rfc3339()),
                created_at: ca.to_rfc3339(),
                tags,
            },
        )
        .collect();

    Ok(Json(leads))
}
