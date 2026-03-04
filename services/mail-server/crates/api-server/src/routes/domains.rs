//! Domain management routes.
//!
//! Handles domain lifecycle:
//! 1. Customer adds a domain via POST /v1/domains
//! 2. Customer configures DNS records (SPF, DKIM, DMARC, Return-Path)
//! 3. Customer triggers verification via POST /v1/domains/:id/verify
//! 4. On successful verification, we **also create the domain identity in SES**
//!    so that SES can send on behalf of the customer's domain.
//! 5. GET /v1/domains/:id/dns-records shows required DNS records.

use aws_sdk_sesv2::types::DkimSigningKeyLength;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use dns_resolver::DnsLookup;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tracing::{info, warn};
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
        .route("/:id/auth-status", get(get_auth_status))
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

    // Fetch domain name before deleting (for SES cleanup)
    let domain_name: Option<(String,)> = sqlx::query_as(
        "SELECT name FROM domains WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await?;

    let result = sqlx::query("DELETE FROM domains WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    // Clean up SES identity (best-effort, non-blocking)
    if let Some((name,)) = domain_name {
        tokio::spawn({
            let state = state.clone();
            async move {
                delete_ses_domain_identity(&state, &name).await;
            }
        });
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

    // ── SES identity creation ──────────────────────────────────
    // When DNS verification passes, create/verify the domain identity in SES
    // so that SES can send on behalf of this domain.
    let mut ses_verified = false;
    if status == "verified" {
        match create_ses_domain_identity(&state, &row.name).await {
            Ok(()) => {
                ses_verified = true;
                info!(domain = %row.name, "SES domain identity created/verified");
            }
            Err(e) => {
                // SES identity creation is best-effort — domain is still verified
                // in our system even if SES call fails (can be retried).
                warn!(domain = %row.name, error = %e, "SES identity creation failed (non-blocking)");
            }
        }
    }

    sqlx::query(
        "UPDATE domains SET spf_verified=$1, dkim_verified=$2, dmarc_verified=$3,
         return_path_verified=$4, status=$5, ses_verified=$6, updated_at=NOW() WHERE id=$7",
    )
    .bind(spf)
    .bind(dkim)
    .bind(dmarc)
    .bind(return_path)
    .bind(status)
    .bind(ses_verified)
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

// ─── SES identity management ───────────────────────────────────

/// Create a domain identity in AWS SES v2 so SES can send from this domain.
///
/// Uses Easy DKIM with 2048-bit RSA keys. SES manages DKIM signing when
/// sending via the SES API — the customer only needs their existing DNS records.
///
/// If the identity already exists, SES returns success (idempotent).
async fn create_ses_domain_identity(state: &AppState, domain: &str) -> Result<(), ApiError> {
    let _ses_provider = &state.ses_provider;

    // We access the raw SES client through the provider's client.
    // For now, construct a fresh client from the provider's region.
    let region = aws_sdk_sesv2::config::Region::new(state.config.aws_region.clone());
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let client = aws_sdk_sesv2::Client::new(&sdk_config);

    // Create the email identity with Easy DKIM
    let dkim_attrs = aws_sdk_sesv2::types::DkimSigningAttributes::builder()
        .domain_signing_selector("apexmail")
        .next_signing_key_length(DkimSigningKeyLength::Rsa2048Bit)
        .build();

    let result = client
        .create_email_identity()
        .email_identity(domain)
        .dkim_signing_attributes(dkim_attrs)
        .configuration_set_name(
            state
                .config
                .ses_configuration_set
                .as_deref()
                .unwrap_or("apexmail-default"),
        )
        .send()
        .await;

    match result {
        Ok(resp) => {
            let dkim_status = resp
                .dkim_attributes()
                .and_then(|d| d.status())
                .map(|s| format!("{:?}", s))
                .unwrap_or_else(|| "unknown".into());

            info!(domain = %domain, dkim_status = %dkim_status, "SES email identity created");
            Ok(())
        }
        Err(e) => {
            let msg = format!("{e}");
            // If identity already exists, that's fine
            if msg.contains("AlreadyExistsException") || msg.contains("already exists") {
                info!(domain = %domain, "SES email identity already exists");
                Ok(())
            } else {
                Err(ApiError::ServiceUnavailable(format!(
                    "SES CreateEmailIdentity failed: {msg}"
                )))
            }
        }
    }
}

/// Delete a domain identity from SES when the domain is removed.
async fn delete_ses_domain_identity(state: &AppState, domain: &str) {
    let region = aws_sdk_sesv2::config::Region::new(state.config.aws_region.clone());
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let client = aws_sdk_sesv2::Client::new(&sdk_config);

    match client
        .delete_email_identity()
        .email_identity(domain)
        .send()
        .await
    {
        Ok(_) => info!(domain = %domain, "SES email identity deleted"),
        Err(e) => warn!(domain = %domain, error = %e, "Failed to delete SES identity (non-blocking)"),
    }
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
}

// ─── Auth Status Handler ───────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DomainAuthStatus {
    pub domain: String,
    pub spf: AuthCheckResult,
    pub dkim: AuthCheckResult,
    pub dmarc: AuthCheckResult,
    pub mx: AuthCheckResult,
    pub return_path: AuthCheckResult,
    pub overall_status: String,
}

#[derive(Debug, Serialize)]
pub struct AuthCheckResult {
    pub status: String,
    pub value: Option<String>,
    pub expected: Option<String>,
}

async fn get_auth_status(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<DomainAuthStatus>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;

    let domain = sqlx::query!(
        "SELECT id, name, spf_verified, dkim_verified, dmarc_verified, mx_verified, return_path_verified
         FROM domains WHERE id = $1 AND tenant_id = $2",
        id,
        auth.tenant_id,
    )
    .fetch_optional(&*state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;

    let check = |verified: bool| AuthCheckResult {
        status: if verified { "pass".into() } else { "fail".into() },
        value: None,
        expected: None,
    };

    let all_pass = domain.spf_verified && domain.dkim_verified && domain.dmarc_verified
        && domain.mx_verified && domain.return_path_verified;
    let any_pass = domain.spf_verified || domain.dkim_verified;

    Ok(Json(DomainAuthStatus {
        domain: domain.name,
        spf: check(domain.spf_verified),
        dkim: check(domain.dkim_verified),
        dmarc: check(domain.dmarc_verified),
        mx: check(domain.mx_verified),
        return_path: check(domain.return_path_verified),
        overall_status: if all_pass {
            "authenticated".into()
        } else if any_pass {
            "partial".into()
        } else {
            "unauthenticated".into()
        },
    }))
}
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
