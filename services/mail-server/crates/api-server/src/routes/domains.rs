//! Domain management routes.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use dns_resolver::DnsLookup;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tracing::warn;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

static DNS_LOOKUP: LazyLock<Result<DnsLookup, String>> = LazyLock::new(|| {
    DnsLookup::new().map_err(|e| format!("DNS resolver initialization failed: {e}"))
});

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_domain).get(list_domains))
        .route("/:id", get(get_domain).delete(delete_domain))
        .route("/:id/verify", post(verify_domain))
        .route("/:id/dns-records", get(get_dns_records))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateDomainRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct DomainResponse {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub spf_verified: bool,
    pub dkim_verified: bool,
    pub dmarc_verified: bool,
    pub return_path_verified: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub hostname: String,
    pub value: String,
    pub priority: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct DnsRecordsResponse {
    pub domain: String,
    pub records: Vec<DnsRecord>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub domain: String,
    pub spf_verified: bool,
    pub dkim_verified: bool,
    pub dmarc_verified: bool,
    pub return_path_verified: bool,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct ListDomainsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
}

fn default_limit() -> i64 {
    50
}

fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    require_scopes(&auth, &["domains:write"])?;

    if !apexmail_lib::validation::is_valid_domain(&body.name) {
        return Err(ApiError::Validation(vec![format!(
            "invalid domain name: {}",
            body.name
        )]));
    }

    // Check for duplicate
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM domains WHERE tenant_id = $1 AND name = $2",
    )
    .bind(auth.tenant_id)
    .bind(&body.name)
    .fetch_one(&state.db)
    .await?;

    if existing > 0 {
        return Err(ApiError::Conflict("domain already exists".into()));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let dkim_selector = format!("apexmail{}", &id.to_string()[..8]);

    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified,
         return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, dkim_selector, created_at, updated_at)
         VALUES ($1,$2,$3,'pending',false,false,false,false,false,false,false,$4,$5,$5)",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .bind(&body.name)
    .bind(&dkim_selector)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(DomainResponse {
            id,
            name: body.name,
            status: "pending".into(),
            spf_verified: false,
            dkim_verified: false,
            dmarc_verified: false,
            return_path_verified: false,
            created_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_domains(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListDomainsQuery>,
) -> Result<Json<Vec<DomainResponse>>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, DomainRow>(
        "SELECT id, name, status, spf_verified, dkim_verified, dmarc_verified, return_path_verified, created_at
         FROM domains WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth.tenant_id)
    .bind(clamp_limit(params.limit, 200))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<DomainResponse>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;

    let row = sqlx::query_as::<_, DomainRow>(
        "SELECT id, name, status, spf_verified, dkim_verified, dmarc_verified, return_path_verified, created_at
         FROM domains WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;

    Ok(Json(row.into()))
}

async fn delete_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["domains:write"])?;

    let result = sqlx::query("DELETE FROM domains WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("domain not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<VerifyResponse>, ApiError> {
    require_scopes(&auth, &["domains:write"])?;

    let row = sqlx::query_as::<_, DomainFullRow>(
        "SELECT id, name, dkim_selector FROM domains WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;

    // Perform real DNS lookups
    let dns = DNS_LOOKUP.as_ref().map_err(|e| {
        ApiError::ServiceUnavailable(format!("DNS verification unavailable: {e}"))
    })?;

    // Check SPF record
    let spf = match dns.lookup_spf(&row.name).await {
        Ok(Some(spf_record)) => {
            // Verify our include is present
            spf_record.raw.contains("include:spf.apexmail.io")
        }
        Ok(None) => false,
        Err(e) => {
            warn!("SPF lookup failed for {}: {}", row.name, e);
            false
        }
    };

    // Check DKIM record
    let selector = row.dkim_selector.as_deref().unwrap_or("apexmail");
    let dkim = match dns.lookup_dkim(selector, &row.name).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            warn!("DKIM lookup failed for {}: {}", row.name, e);
            false
        }
    };

    // Check DMARC record
    let dmarc = match dns.lookup_dmarc(&row.name).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            warn!("DMARC lookup failed for {}: {}", row.name, e);
            false
        }
    };

    // Check return path (CNAME for bounces subdomain)
    let return_path = match dns
        .lookup_txt(&format!("bounces.{}", row.name))
        .await
    {
        Ok(txts) => txts.iter().any(|t| t.contains("apexmail.io")),
        Err(_) => false,
    };

    let status = if spf && dkim && dmarc { "verified" } else { "pending" };

    sqlx::query(
        "UPDATE domains SET spf_verified=$1, dkim_verified=$2, dmarc_verified=$3,
         return_path_verified=$4, status=$5, updated_at=NOW() WHERE id=$6",
    )
    .bind(spf)
    .bind(dkim)
    .bind(dmarc)
    .bind(return_path)
    .bind(status)
    .bind(id)
    .execute(&state.db)
    .await?;

    Ok(Json(VerifyResponse {
        domain: row.name,
        spf_verified: spf,
        dkim_verified: dkim,
        dmarc_verified: dmarc,
        return_path_verified: return_path,
        status: status.into(),
    }))
}

async fn get_dns_records(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<DnsRecordsResponse>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;

    let row = sqlx::query_as::<_, DomainFullRow>(
        "SELECT id, name, dkim_selector FROM domains WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;

    let selector = row.dkim_selector.unwrap_or_else(|| "apexmail".into());

    let records = vec![
        DnsRecord {
            record_type: "TXT".into(),
            hostname: row.name.clone(),
            value: "v=spf1 include:spf.apexmail.io ~all".into(),
            priority: None,
        },
        DnsRecord {
            record_type: "CNAME".into(),
            hostname: format!("{selector}._domainkey.{}", row.name),
            value: format!("{selector}.dkim.apexmail.io"),
            priority: None,
        },
        DnsRecord {
            record_type: "TXT".into(),
            hostname: format!("_dmarc.{}", row.name),
            value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.io".into(),
            priority: None,
        },
        DnsRecord {
            record_type: "MX".into(),
            hostname: format!("bounce.{}", row.name),
            value: "feedback-smtp.apexmail.io".into(),
            priority: Some(10),
        },
    ];

    Ok(Json(DnsRecordsResponse {
        domain: row.name,
        records,
    }))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DomainRow {
    id: Uuid,
    name: String,
    status: String,
    spf_verified: bool,
    dkim_verified: bool,
    dmarc_verified: bool,
    return_path_verified: bool,
    created_at: DateTime<Utc>,
}

impl From<DomainRow> for DomainResponse {
    fn from(r: DomainRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            status: r.status,
            spf_verified: r.spf_verified,
            dkim_verified: r.dkim_verified,
            dmarc_verified: r.dmarc_verified,
            return_path_verified: r.return_path_verified,
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

#[derive(sqlx::FromRow)]
#[allow(unused)]
struct DomainFullRow {
    id: Uuid,
    name: String,
    dkim_selector: Option<String>,
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_domain_request_deser() {
        let json = r#"{"name":"example.com"}"#;
        let req: CreateDomainRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "example.com");
    }

    #[test]
    fn test_dns_records_generation() {
        let records = vec![
            DnsRecord {
                record_type: "TXT".into(),
                hostname: "example.com".into(),
                value: "v=spf1 include:spf.apexmail.io ~all".into(),
                priority: None,
            },
        ];
        let json = serde_json::to_value(&records).unwrap();
        assert_eq!(json[0]["record_type"], "TXT");
    }

    #[test]
    fn test_domain_response_serialisation() {
        let resp = DomainResponse {
            id: Uuid::nil(),
            name: "example.com".into(),
            status: "verified".into(),
            spf_verified: true,
            dkim_verified: true,
            dmarc_verified: true,
            return_path_verified: false,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["spf_verified"], true);
    }
}
