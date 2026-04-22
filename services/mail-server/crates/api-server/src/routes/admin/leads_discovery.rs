//! Lead discovery endpoint — sources and discovered leads.
//!
//! Migrated from:apps/control-plane/src/app/api/leads/discovery/route.ts (83 lines)

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_discovery))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryResponse {
    pub sources: Vec<DiscoverySource>,
    pub leads: Vec<DiscoveredLead>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverySource {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub enabled: bool,
    pub last_run: Option<String>,
    pub leads_found: i64,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredLead {
    pub id: String,
    pub company_name: Option<String>,
    pub domain: Option<String>,
    pub source: Option<String>,
    pub category: Option<String>,
    pub description: Option<String>,
    pub found_at: String,
    pub imported: bool,
}

async fn get_discovery(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<DiscoveryResponse>, ApiError> {
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
        return Ok(Json(DiscoveryResponse { sources: vec![], leads: vec![] }));
    }

// Sources breakdown from sales_leads.source
    let source_rows = sqlx::query_as::<_, (Option<String>, i64)>(
        "SELECT source, COUNT(*) as cnt FROM sales_leads GROUP BY source ORDER BY cnt DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let icon_for = |name: &str| -> &str {
        match name.to_lowercase().as_str() {
            "linkedin" => "🔗",
            "website" => "🌐",
            "referral" => "👥",
            "conference" => "🎤",
            "cold_outreach" | "cold outreach" => "📧",
            _ => "📋",
        }
    };

    let sources: Vec<DiscoverySource> = source_rows
        .into_iter()
        .map(|(src, cnt)| {
            let name = src.clone().unwrap_or_else(|| "Unknown".into());
            DiscoverySource {
                id: name.to_lowercase().replace(' ', "_"),
                icon: icon_for(&name).into(),
                enabled: true,
                last_run: None,
                leads_found: cnt,
                status: "active".into(),
                name,
            }
        })
        .collect();

// Recent leads
    let lead_rows = sqlx::query_as::<_, (
        String, Option<String>, Option<String>, Option<String>,
        Option<String>, Option<String>, chrono::DateTime<chrono::Utc>,
    )>(
        "SELECT id::text, company_name, domain, source, stage, description, created_at
         FROM sales_leads ORDER BY created_at DESC LIMIT 100",
    )
    .fetch_all(&state.db)
    .await?;

    let leads: Vec<DiscoveredLead> = lead_rows
        .into_iter()
        .map(|(id, cn, dom, src, stage, desc, ca)| DiscoveredLead {
            id, company_name: cn, domain: dom, source: src,
            category: stage, description: desc,
            found_at: ca.to_rfc3339(),
            imported: true,
        })
        .collect();

    Ok(Json(DiscoveryResponse { sources, leads }))
}
