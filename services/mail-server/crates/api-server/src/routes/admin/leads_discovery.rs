//! Lead discovery endpoint — sources and discovered leads.
//!

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::presentation::leads::source_icon;
use crate::state::AppState;

/// The discovery import read, as one named function.
///
/// Named so a test executes exactly what the handler executes — the previous
/// version selected `stage`/`industry`, which do not exist on the canonical
/// `sales_leads`, so the endpoint failed on every call unnoticed.
fn discovered_leads_sql() -> String {
    format!(
        "{cte}
         SELECT l.id::text, l.company_name, l.domain, l.source, cl.status,
                COALESCE(a.industry, ''), cl.created_at
         FROM sales_leads l
         JOIN canonical_leads cl ON cl.id = l.id AND cl.tenant_id = l.tenant_id
         LEFT JOIN sales_accounts a
                ON a.id = l.account_id AND a.tenant_id = l.tenant_id
         ORDER BY cl.created_at DESC
         LIMIT 100",
        cte = super::sales::CANONICAL_LEAD_CTE
    )
}

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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    // Check table exists
    let exists: Option<(bool,)> = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relname = 'sales_leads')",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    if !exists.map(|r| r.0).unwrap_or(false) {
        return Ok(Json(DiscoveryResponse {
            sources: vec![],
            leads: vec![],
        }));
    }

    // Sources breakdown from sales_leads.source
    let source_rows = sqlx::query_as::<_, (Option<String>, i64)>(
        "SELECT source, COUNT(*) as cnt FROM sales_leads GROUP BY source ORDER BY cnt DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let sources: Vec<DiscoverySource> = source_rows
        .into_iter()
        .map(|(src, cnt)| {
            let name = src.clone().unwrap_or_else(|| "Unknown".into());
            DiscoverySource {
                id: name.to_lowercase().replace(' ', "_"),
                icon: source_icon(&name).into(),
                enabled: true,
                last_run: None,
                leads_found: cnt,
                status: "active".into(),
                name,
            }
        })
        .collect();

    // Recent leads
    let lead_rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        // `stage` and `industry` DO NOT EXIST on the canonical `sales_leads`
        // (the legacy lineage had them), so this query failed with 42703 on
        // every call. `category` is now the canonical status derivation and
        // `description` is the account's industry — which is where industry
        // actually lives in the canonical model, and is why the old
        // "industry on the lead" assumption was wrong in the first place.
        &discovered_leads_sql(),
    )
    .fetch_all(&state.db)
    .await?;

    let leads: Vec<DiscoveredLead> = lead_rows
        .into_iter()
        .map(|(id, cn, dom, src, stage, desc, ca)| DiscoveredLead {
            id,
            company_name: cn,
            domain: dom,
            source: src,
            category: stage,
            description: desc,
            found_at: ca.to_rfc3339(),
            imported: true,
        })
        .collect();

    Ok(Json(DiscoveryResponse { sources, leads }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression this file exists for: both queries selected columns that
    /// do not exist on the canonical `sales_leads` (`stage`, `industry`,
    /// `last_contacted_at`) and failed with 42703 on every request. There was
    /// no test that EXECUTED them, so the drift went unnoticed. Executing the
    /// exact statement the handler runs is what closes that gap.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn discovery_query_executes_against_the_canonical_schema() {
        let Some(pool) = crate::test_db::canonical_pool("discovery_leads_sql").await else {
            return;
        };
        let tenant = format!(
            "crmlead-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );

        // A canonical lead: account + contact + point + the bridge row the CTE
        // joins through.
        let account_id = uuid::Uuid::new_v4();
        let contact_id = uuid::Uuid::new_v4();
        let lead_id = format!("lead-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, industry) \
             VALUES ($1, $2, 'Canonical Co', $3, 'Email Infrastructure')",
        )
        .bind(account_id)
        .bind(&tenant)
        .bind(format!("{account_id}.example"))
        .execute(&pool)
        .await
        .expect("seed account");
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) \
             VALUES ($1, $2, $3, 'Canonical Prospect')",
        )
        .bind(contact_id)
        .bind(&tenant)
        .bind(account_id)
        .execute(&pool)
        .await
        .expect("seed contact");
        sqlx::query(
            "INSERT INTO sales_contact_points \
                 (id, tenant_id, contact_id, channel, value, normalized_value, verification) \
             VALUES ($1, $2, $3, 'email', $4, lower($4), 'valid')",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&tenant)
        .bind(contact_id)
        .bind(format!(
            "prospect-{}@example.com",
            &contact_id.simple().to_string()[..8]
        ))
        .execute(&pool)
        .await
        .expect("seed contact point");
        sqlx::query(
            "INSERT INTO sales_leads \
                 (id, tenant_id, company_name, domain, status, score, source, account_id, contact_id) \
             VALUES ($1, $2, 'Canonical Co', $3, 'new', 42, 'fixture', $4, $5)",
        )
        .bind(&lead_id)
        .bind(&tenant)
        .bind(format!("{account_id}.example"))
        .bind(account_id)
        .bind(contact_id)
        .execute(&pool)
        .await
        .expect("seed bridge lead");

        // Exactly the handler's tuple: id, company, domain, source, status,
        // industry, created_at.
        let rows: Vec<(
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(&discovered_leads_sql())
            .fetch_all(&pool)
            .await
            .expect("the handler query must execute against the canonical schema");

        let row = rows
            .iter()
            .find(|r| r.0 == lead_id)
            .expect("the seeded lead must be returned");
        assert_eq!(
            row.5.as_deref(),
            Some("Email Infrastructure"),
            "description is the ACCOUNT industry — industry never lived on the lead"
        );

        for stmt in [
            "DELETE FROM sales_leads WHERE tenant_id = $1",
            "DELETE FROM sales_contact_points WHERE tenant_id = $1",
            "DELETE FROM sales_contacts WHERE tenant_id = $1",
            "DELETE FROM sales_accounts WHERE tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(&tenant).execute(&pool).await.ok();
        }
    }
}
