//! Campaign listing endpoint backed by the canonical sales campaign model.
//!
//! The control plane's own campaign execution path was retired in migration
//! 200 (its rows were never consumed by the production scheduler). This route
//! reads the canonical `sales_campaigns` + `sales_campaign_recipients` tables
//! written by the sales-autopilot engine.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::super::helpers::table_exists;
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
    pub total_recipients: i64,
    pub sent: i64,
    pub opened: i64,
    pub clicked: i64,
    pub replied: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Tuple shape shared by both canonical queries:
/// id, name, status, total_recipients, sent, opened, clicked, replied,
/// created_at, updated_at.
type CampaignTuple = (
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
);

async fn list_campaigns(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<CampaignsQuery>,
) -> Result<Json<Vec<CampaignRow>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    // `sales_campaigns` is canonical (migration 197); the recipient table is
    // created by the sales service's bootstrap, so probe it before joining.
    if !table_exists(&state.db, "sales_campaigns").await {
        return Ok(Json(vec![]));
    }
    let has_recipients = table_exists(&state.db, "sales_campaign_recipients").await;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    // `sales_campaigns` has no updated_at column; created_at is the stable
    // timestamp both lineages share. replied has no canonical campaign column
    // (reply handling lives on `sales_reply_classifications`), so it is 0.
    let rows: Vec<CampaignTuple> = if has_recipients {
        sqlx::query_as(
            "SELECT c.id::text, c.name, c.status,
                    COUNT(r.email)::bigint,
                    COALESCE(c.sent, 0),
                    COALESCE(c.opened, 0),
                    COALESCE(c.clicked, 0),
                    0::bigint,
                    c.created_at, c.created_at
             FROM sales_campaigns c
             LEFT JOIN sales_campaign_recipients r ON r.campaign_id = c.id
             GROUP BY c.id, c.name, c.status, c.sent, c.opened, c.clicked, c.created_at
             ORDER BY c.created_at DESC
             LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as(
            "SELECT c.id::text, c.name, c.status,
                    0::bigint,
                    COALESCE(c.sent, 0),
                    COALESCE(c.opened, 0),
                    COALESCE(c.clicked, 0),
                    0::bigint,
                    c.created_at, c.created_at
             FROM sales_campaigns c
             ORDER BY c.created_at DESC
             LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    let campaigns: Vec<CampaignRow> = rows
        .into_iter()
        .map(
            |(id, name, status, total, sent, opened, clicked, replied, ca, ua)| CampaignRow {
                id,
                name,
                status,
                total_recipients: total,
                sent,
                opened,
                clicked,
                replied,
                created_at: ca.to_rfc3339(),
                updated_at: ua.to_rfc3339(),
            },
        )
        .collect();

    Ok(Json(campaigns))
}

#[cfg(test)]
mod tests {
    /// Fragments are assembled at runtime so the test source itself does not
    /// contain the forbidden strings it scans for.
    #[test]
    fn campaigns_module_reads_the_canonical_tables_only() {
        let source = include_str!("campaigns.rs");
        for fragment in [
            ["drip", "campaigns"].join("_"),
            ["CREATE", "TABLE"].join(" "),
            ["ALTER", "TABLE"].join(" "),
            ["pg", "class"].join("_"),
        ] {
            assert!(
                !source.contains(&fragment),
                "campaigns.rs must not contain the retired artifact `{fragment}`"
            );
        }
        // The bare (retired) recipient table must appear nowhere; every
        // occurrence must carry the canonical sales_ prefix.
        let bare_recipients = ["campaign", "recipients"].join("_");
        let canonical_recipients = ["sales_", "campaign_", "recipients"].concat();
        assert_eq!(
            source.matches(&bare_recipients).count(),
            source.matches(&canonical_recipients).count(),
            "every recipient-table reference must be the canonical sales_ form"
        );
        assert!(source.contains("sales_campaigns"));
    }

    mod adversarial_tests {
        use axum::http::StatusCode;

        use crate::app::test_support::adv::AdvEnv;

        /// Canonical migration 201 provisions sales_campaign_recipients; the
        /// handler still probes because sales-service bootstraps may lag.
        /// The no-join arm therefore needs the table DROPPED inside this
        /// test's own database.
        async fn drop_recipients(pool: &sqlx::PgPool) {
            sqlx::query("DROP TABLE IF EXISTS sales_campaign_recipients")
                .execute(pool)
                .await
                .expect("drop recipients table");
        }

        async fn seed_sales_campaign(
            pool: &sqlx::PgPool,
            name: &str,
            status: &str,
            sent: i64,
            opened: i64,
            clicked: i64,
            days_ago: i32,
        ) -> uuid::Uuid {
            let id = uuid::Uuid::new_v4();
            sqlx::query(
                "INSERT INTO sales_campaigns (id, tenant_id, name, template_id, audience, status, sent, opened, clicked, created_at)
                 VALUES ($1, 'system', $2, 'tpl', 'audience', $3, $4, $5, $6,
                         NOW() - ($7 || ' days')::interval)",
            )
            .bind(id)
            .bind(name)
            .bind(status)
            .bind(sent)
            .bind(opened)
            .bind(clicked)
            .bind(days_ago.to_string())
            .execute(pool)
            .await
            .expect("seed sales campaign");
            id
        }

        #[tokio::test]
        async fn campaigns_list_without_the_recipients_table_still_reports() {
            // Canonical schema has sales_campaigns but NOT
            // sales_campaign_recipients (the sales service creates it at
            // bootstrap): the no-join arm must list campaigns with zeroed
            // recipient counts.
            let Some(pool) = crate::test_db::canonical_pool("adm_camp_norec").await else {
                return;
            };
            drop_recipients(&pool).await;
            let env = AdvEnv::admin(pool.clone()).await;
            let old = seed_sales_campaign(&pool, "older blast", "completed", 10, 5, 2, 5).await;
            seed_sales_campaign(&pool, "newer blast", "running", 3, 0, 0, 1).await;

            let (status, body) = env.get("/v1/admin/campaigns").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let rows = body.as_array().expect("array");
            assert_eq!(rows.len(), 2);
            // Newest first.
            assert_eq!(rows[0]["name"], "newer blast");
            assert_eq!(rows[0]["status"], "running");
            assert_eq!(rows[0]["totalRecipients"], 0);
            assert_eq!(rows[0]["sent"], 3);
            assert_eq!(rows[1]["name"], "older blast");
            assert_eq!(rows[1]["totalRecipients"], 0);
            assert_eq!(rows[1]["sent"], 10);
            assert_eq!(rows[1]["opened"], 5);
            assert_eq!(rows[1]["clicked"], 2);
            // replied is not a canonical campaign column — always 0.
            assert_eq!(rows[1]["replied"], 0);
            assert_eq!(rows[1]["id"], old.to_string());
            assert!(rows[0]["createdAt"]
                .as_str()
                .is_some_and(|t| t.starts_with("20")));
            assert_eq!(rows[0]["updatedAt"], rows[0]["createdAt"]);
        }

        #[tokio::test]
        async fn campaigns_list_joins_the_recipients_table_when_present() {
            let Some(pool) = crate::test_db::canonical_pool("adm_camp_rec").await else {
                return;
            };
            let env = AdvEnv::admin(pool.clone()).await;
            // The canonical schema already carries sales_campaign_recipients
            // (migration 201): the join arm runs against it as provisioned.
            let campaign =
                seed_sales_campaign(&pool, "joined blast", "completed", 0, 0, 0, 0).await;
            for email in ["a@example.com", "b@example.com", "c@example.com"] {
                sqlx::query(
                    "INSERT INTO sales_campaign_recipients (campaign_id, email) VALUES ($1, $2)",
                )
                .bind(campaign)
                .bind(email)
                .execute(&pool)
                .await
                .expect("seed recipient");
            }

            let (status, body) = env.get("/v1/admin/campaigns").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let rows = body.as_array().expect("array");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["totalRecipients"], 3);
        }

        #[tokio::test]
        async fn campaigns_pagination_clamps_hostile_params() {
            let Some(pool) = crate::test_db::canonical_pool("adm_camp_page").await else {
                return;
            };
            let env = AdvEnv::admin(pool.clone()).await;
            for i in 0..3 {
                seed_sales_campaign(&pool, &format!("page-{i}"), "draft", 0, 0, 0, i).await;
            }
            // Negative offset floors to 0; oversized limit clamps to 200.
            let (status, body) = env.get("/v1/admin/campaigns?limit=100000&offset=-9").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body.as_array().map(Vec::len), Some(3));

            let (status, body) = env.get("/v1/admin/campaigns?limit=0").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            // limit=0 clamps to 1 — a page of exactly one row.
            assert_eq!(body.as_array().map(Vec::len), Some(1));

            let (status, body) = env.get("/v1/admin/campaigns?limit=2&offset=2").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let rows = body.as_array().expect("array");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["name"], "page-2");
        }

        #[tokio::test]
        async fn campaigns_reject_unknown_query_fields() {
            let Some(pool) = crate::test_db::canonical_pool("adm_camp_unknown").await else {
                return;
            };
            let env = AdvEnv::admin(pool).await;
            let (status, _body) = env.get("/v1/admin/campaigns?limit=5&bogus=1").await;
            // axum's Query extractor rejects unknown fields with 400.
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn campaigns_require_the_wildcard_scope() {
            let Some(pool) = crate::test_db::canonical_pool("adm_camp_scope").await else {
                return;
            };
            let key =
                crate::app::test_support::seed_api_key_for(&pool, "system", &["sales:read"]).await;
            let env = AdvEnv::over(pool, key).await;
            let (status, body) = env.get("/v1/admin/campaigns").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        }

        #[tokio::test]
        async fn campaigns_reject_customer_tenants() {
            let Some(pool) = crate::test_db::canonical_pool("adm_camp_tenant").await else {
                return;
            };
            let (env, _tenant) = AdvEnv::tenant(pool, &["*"]).await;
            let (status, body) = env.get("/v1/admin/campaigns").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        }
    }
}
