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
}
