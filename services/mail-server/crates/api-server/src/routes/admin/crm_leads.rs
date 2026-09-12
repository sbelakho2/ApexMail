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

/// The CRM-leads read, as one named function.
///
/// Named so a test can execute EXACTLY what the handler executes: the previous
/// version selected `stage`/`last_contacted_at`, which do not exist on the
/// canonical `sales_leads`, and nothing caught it because no test ever ran the
/// query.
fn crm_leads_sql() -> String {
    format!(
        "{cte}
         SELECT cl.id::text, cl.company_name, cl.domain, cl.contact_email,
                cl.contact_name, cl.status, cl.score, cl.source,
                lc.last_contacted_at, cl.created_at,
                COALESCE(cl.tags, '[]'::jsonb)
         FROM canonical_leads cl
         LEFT JOIN LATERAL (
             SELECT MAX(se.executed_at) AS last_contacted_at
             FROM sales_step_executions se
             JOIN sales_enrollments e ON e.id = se.enrollment_id
             WHERE e.contact_id = cl.contact_id AND e.tenant_id = cl.tenant_id
               AND se.executed_at IS NOT NULL
         ) lc ON TRUE
         WHERE cl.tenant_id = $3
         ORDER BY cl.score DESC NULLS LAST, cl.created_at DESC
         LIMIT $1 OFFSET $2",
        cte = super::sales::CANONICAL_LEAD_CTE
    )
}

async fn list_crm_leads(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<CrmLeadsQuery>,
) -> Result<Json<Vec<CrmLead>>, ApiError> {
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
        // API-104: Scope CRM leads by tenant_id to prevent cross-tenant access.
        //
        // `stage` and `last_contacted_at` DO NOT EXIST on the canonical
        // `sales_leads` (they were legacy-lineage columns), so the previous
        // query failed with 42703 on every call — this endpoint had no test
        // that executed it, only none at all. `stage` is now the canonical
        // status derivation (shared with the CP list so the two cannot
        // disagree) and `last_contacted_at` is the newest executed sequence
        // step, which is what "last contacted" means in the canonical model.
        &crm_leads_sql(),
    )
    .bind(limit)
    .bind(offset)
    .bind(&auth.tenant_id)
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
    async fn crm_leads_query_executes_against_the_canonical_schema() {
        let Some(pool) = crate::test_db::canonical_pool("crm_leads_sql").await else {
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

        let rows: Vec<(
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
        )> = sqlx::query_as(&crm_leads_sql())
            .bind(50i64)
            .bind(0i64)
            .bind(&tenant)
            .fetch_all(&pool)
            .await
            .expect("the handler query must execute against the canonical schema");

        let row = rows
            .iter()
            .find(|r| r.0 == lead_id)
            .expect("the seeded lead must be returned");
        assert_eq!(
            row.5.as_deref(),
            Some("new"),
            "stage is the canonical status derivation, not the frozen legacy column"
        );
        assert_eq!(row.6, Some(42), "the bounded projection score is returned");

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
