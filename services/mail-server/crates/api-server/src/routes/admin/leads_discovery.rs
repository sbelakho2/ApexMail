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
         SELECT cl.id::text, cl.company_name, cl.domain, cl.source, cl.status,
                COALESCE(a.industry, ''), cl.created_at
         FROM canonical_leads cl
         LEFT JOIN sales_accounts a
                ON a.id = cl.account_id AND a.tenant_id = cl.tenant_id
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
    #[tokio::test]
    async fn discovery_query_executes_against_the_canonical_schema() {
        let Some(pool) = crate::test_db::canonical_pool("discovery_leads_sql").await else {
            return;
        };
        let tenant = format!(
            "crmlead-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );

        // A canonical lead: account + contact + point + the id mapping the
        // derived view (and the CTE) reads.
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
            "UPDATE sales_contacts \
                SET legacy_lead_id = $1, lead_source = 'fixture', lead_score = 42 \
              WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&lead_id)
        .bind(contact_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("map the contact as a lead");

        // A discovery-imported lead has the writer's exact shape: a contact
        // carrying the id mapping and lead projection, NO contact point
        // (nothing is fabricated), empty full_name.
        let discovered_lead_id = format!(
            "lead-discovery-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..11]
        );
        sqlx::query(
            "INSERT INTO sales_contacts \
                 (id, tenant_id, account_id, full_name, legacy_lead_id, \
                  lead_source, lead_created_at, lead_updated_at) \
             VALUES ($1, $2, $3, '', $4, 'discovery', NOW(), NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&tenant)
        .bind(account_id)
        .bind(&discovered_lead_id)
        .execute(&pool)
        .await
        .expect("seed discovery-shaped lead");

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

        // The discovery insert is visible in the CP list immediately.
        let discovered = rows
            .iter()
            .find(|r| r.0 == discovered_lead_id)
            .expect("a discovery-imported lead must be visible in the CP list");
        assert_eq!(discovered.3.as_deref(), Some("discovery"));
        assert_eq!(discovered.4.as_deref(), Some("new"));
        assert_eq!(
            discovered.5.as_deref(),
            Some("Email Infrastructure"),
            "the discovery lead inherits the account industry"
        );

        for stmt in [
            "UPDATE sales_contacts SET legacy_lead_id = NULL WHERE tenant_id = $1",
            "DELETE FROM sales_contact_points WHERE tenant_id = $1",
            "DELETE FROM sales_contacts WHERE tenant_id = $1",
            "DELETE FROM sales_accounts WHERE tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(&tenant).execute(&pool).await.ok();
        }
    }
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    /// Seed one canonical lead (the migration-223 view's base rows) for
    /// `tenant`: an account, a contact carrying the lead mapping, and an
    /// email contact point.
    async fn seed_canonical_lead(
        pool: &sqlx::PgPool,
        tenant: &str,
        company: &str,
        source: &str,
        score: i32,
    ) -> String {
        let account_id = uuid::Uuid::new_v4();
        let contact_id = uuid::Uuid::new_v4();
        let lead_id = format!("lead-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, industry)
             VALUES ($1, $2, $3, $4, 'Email Infrastructure')",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(company)
        .bind(format!(
            "{}-{}.example",
            company.to_lowercase(),
            &account_id.simple().to_string()[..6]
        ))
        .execute(pool)
        .await
        .expect("seed account");
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name)
             VALUES ($1, $2, $3, 'Canonical Prospect')",
        )
        .bind(contact_id)
        .bind(tenant)
        .bind(account_id)
        .execute(pool)
        .await
        .expect("seed contact");
        sqlx::query(
            "UPDATE sales_contacts
                SET legacy_lead_id = $1, lead_source = $2, lead_score = $3
              WHERE id = $4",
        )
        .bind(&lead_id)
        .bind(source)
        .bind(score)
        .bind(contact_id)
        .execute(pool)
        .await
        .expect("map the contact as a lead");
        lead_id
    }

    #[tokio::test]
    async fn discovery_reports_sources_and_leads_for_the_operator() {
        let Some(pool) = crate::test_db::canonical_pool("adv_discovery").await else {
            return;
        };
        let env = crate::app::test_support::adv::AdvEnv::admin(pool.clone()).await;
        let tenant = format!(
            "advdisc{}",
            &uuid::Uuid::new_v4().simple().to_string()[..14]
        );
        seed_canonical_lead(&pool, &tenant, "Acme Radar", "linkedin", 80).await;
        seed_canonical_lead(&pool, &tenant, "Beta Radar", "linkedin", 60).await;
        seed_canonical_lead(&pool, &tenant, "Gamma Tools", "apex-plugin", 40).await;

        let (status, body) = env.get("/v1/admin/leads/discovery").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let sources = body["sources"].as_array().expect("sources");
        assert_eq!(sources.len(), 2, "one per distinct source");
        let linkedin = sources
            .iter()
            .find(|s| s["name"] == "linkedin")
            .expect("linkedin source");
        assert_eq!(linkedin["leadsFound"], 2);
        assert_eq!(linkedin["enabled"], true);
        assert_eq!(linkedin["status"], "active");
        assert!(linkedin["icon"].as_str().is_some_and(|i| !i.is_empty()));

        let leads = body["leads"].as_array().expect("leads");
        assert_eq!(leads.len(), 3);
        assert!(leads.iter().all(|l| l["imported"] == true));
        assert!(leads
            .iter()
            .all(|l| l["foundAt"].as_str().is_some_and(|t| t.starts_with("20"))));
        // The industry from the joined account surfaces as the description.
        assert!(leads
            .iter()
            .all(|l| l["description"] == "Email Infrastructure"));
    }

    #[tokio::test]
    async fn discovery_with_no_leads_is_an_empty_report() {
        let Some(pool) = crate::test_db::canonical_pool("adv_discovery_empty").await else {
            return;
        };
        let env = crate::app::test_support::adv::AdvEnv::admin(pool).await;
        let (status, body) = env.get("/v1/admin/leads/discovery").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["sources"].as_array().map(Vec::len), Some(0));
        assert_eq!(body["leads"].as_array().map(Vec::len), Some(0));
    }

    #[tokio::test]
    async fn discovery_requires_the_wildcard_scope_and_system_tenant() {
        let Some(pool) = crate::test_db::canonical_pool("adv_discovery_gates").await else {
            return;
        };
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["sales:read"]).await;
        let scoped = crate::app::test_support::adv::AdvEnv::over(pool.clone(), key).await;
        let (status, body) = scoped.get("/v1/admin/leads/discovery").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (customer, _tenant) = crate::app::test_support::adv::AdvEnv::tenant(pool, &["*"]).await;
        let (status, body) = customer.get("/v1/admin/leads/discovery").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}
