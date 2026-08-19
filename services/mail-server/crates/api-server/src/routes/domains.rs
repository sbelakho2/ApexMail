//! Domain management routes.
//!
//! Handles domain lifecycle://! 1. Customer adds a domain via POST /v1/domains
//! 2. Customer configures DNS records (SPF, DKIM, DMARC, Return-Path)
//! 3. Customer triggers verification via POST /v1/domains/:id/verify
//! 4. On successful verification, we **also create the domain identity in SES**
//! so that SES can send on behalf of the customer's domain.
//! 5. GET /v1/domains/:id/dns-records shows required DNS records.

use super::helpers::{clamp_limit, default_limit};
use apexmail_lib::cache::cache_del;
use apexmail_lib::dkim::{
    decrypt_dkim_private_key, dkim_private_key_aad, dkim_public_keys_match,
    dkim_txt_record_value, encrypt_dkim_private_key, generate_dkim_keypair,
    is_encrypted_dkim_private_key, public_key_base64_from_private_key_pem,
    ses_private_key_base64_from_pem,
};
use aws_sdk_sesv2::types::{
    BehaviorOnMxFailure, DkimSigningAttributes, DkimSigningAttributesOrigin, DkimStatus,
    MailFromDomainStatus, VerificationStatus,
};
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

use crate::config::Config;
use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::routes::system_sender::{SYSTEM_DOMAIN, SYSTEM_DOMAIN_ID, SYSTEM_TENANT_ID};
use crate::state::AppState;

static DNS_LOOKUP: LazyLock<Result<DnsLookup, String>> = LazyLock::new(|| {
    DnsLookup::new().map_err(|e| format!("DNS resolver initialization failed: {e}"))
});

const DEFAULT_DKIM_SELECTOR: &str = "apexmail2026";
const RETURN_PATH_LABEL: &str = "bounce";
const SES_RETURN_PATH_MX_PRIORITY: u16 = 10;
const SPF_INCLUDE_MECHANISM: &str = "include:amazonses.com";
const SPF_RECORD_VALUE: &str = "v=spf1 include:amazonses.com ~all";
const DMARC_RECORD_VALUE: &str = "v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.io";

fn effective_dkim_selector(selector: Option<&str>) -> &str {
    selector
        .filter(|selector| !selector.trim().is_empty())
        .unwrap_or(DEFAULT_DKIM_SELECTOR)
}

fn return_path_hostname(domain: &str) -> String {
    format!("{RETURN_PATH_LABEL}.{domain}")
}

fn return_path_mx_target(aws_region: &str) -> String {
    format!("feedback-smtp.{aws_region}.amazonses.com")
}

fn dkim_hostname(selector: &str, domain: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

fn dkim_dns_record(selector: &str, domain: &str, public_key: &str) -> DnsRecord {
    DnsRecord {
        record_type: "TXT".into(),
        hostname: dkim_hostname(selector, domain),
        value: dkim_txt_record_value(public_key),
        priority: None,
    }
}

fn return_path_spf_dns_record(domain: &str) -> DnsRecord {
    DnsRecord {
        record_type: "TXT".into(),
        hostname: return_path_hostname(domain),
        value: SPF_RECORD_VALUE.into(),
        priority: None,
    }
}

fn return_path_dns_record(domain: &str, aws_region: &str) -> DnsRecord {
    DnsRecord {
        record_type: "MX".into(),
        hostname: return_path_hostname(domain),
        value: return_path_mx_target(aws_region),
        priority: Some(SES_RETURN_PATH_MX_PRIORITY),
    }
}

fn required_sender_dns_records(
    domain: &str,
    selector: &str,
    public_key: &str,
    aws_region: &str,
    ses_transport: bool,
) -> Vec<DnsRecord> {
    let mut records = vec![
        dkim_dns_record(selector, domain, public_key),
        DnsRecord {
            record_type: "TXT".into(),
            hostname: format!("_dmarc.{domain}"),
            value: DMARC_RECORD_VALUE.into(),
            priority: None,
        },
    ];

    if ses_transport {
        records.insert(0, return_path_spf_dns_record(domain));
        records.push(return_path_dns_record(domain, aws_region));
    }

    records
}

fn new_dkim_selector() -> String {
    format!("am-{}", Uuid::new_v4().simple())
}

fn dkim_key_provisioning_error(error: impl std::fmt::Display) -> ApiError {
    warn!(error = %error, "DKIM key provisioning failed");
    ApiError::ServiceUnavailable(
        "DKIM key provisioning is temporarily unavailable; please retry shortly".into(),
    )
}

fn dns_target_matches(target: &str, expected: &str) -> bool {
    target
        .trim_end_matches('.')
        .eq_ignore_ascii_case(expected.trim_end_matches('.'))
}

/// Serialize mutations for a tenant's domain quota and names. Hash collisions
/// only add harmless serialization; they cannot grant an extra quota slot.
async fn lock_tenant_domain_mutations(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Serialize all lifecycle operations for an SES identity, which is keyed by
/// domain name across the AWS account rather than by the local domain row ID.
async fn lock_domain_identity(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    domain: &str,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("ses-identity:{domain}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn sender_dns_is_ready(
    spf_verified: bool,
    dkim_verified: bool,
    dmarc_verified: bool,
    return_path_verified: bool,
    ses_transport: bool,
) -> bool {
    // SMTP sends with the visible sender as its envelope sender. DKIM alignment
    // satisfies DMARC there, so an SES-only custom MAIL FROM record is neither
    // used nor required. SES requires its custom MAIL FROM SPF/MX pair.
    dkim_verified
        && dmarc_verified
        && (!ses_transport || (spf_verified && return_path_verified))
}

    fn domain_name_conflict(error: &sqlx::Error) -> bool {
        error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23505")
    }

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
#[serde(deny_unknown_fields)]
pub struct CreateDomainRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct DomainResponse {
    pub id: String,
    pub name: String,
    pub status: String,
    pub ses_verified: bool,
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
#[serde(deny_unknown_fields)]
pub struct ListDomainsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    require_scopes(&auth, &["domains:write"])?;

    let domain_name = body
        .name
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if !apexmail_lib::validation::is_valid_domain(&domain_name) {
        return Err(ApiError::Validation(vec![format!(
            "invalid domain name: {}",
            domain_name
        )]));
    }

    let mut tx = state.db.begin().await?;
    lock_tenant_domain_mutations(&mut tx, &auth.tenant_id).await?;
    lock_domain_identity(&mut tx, &domain_name).await?;

    let existing: (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM domains WHERE tenant_id = $1 AND name = $2)")
            .bind(&auth.tenant_id)
            .bind(&domain_name)
            .fetch_one(&mut *tx)
            .await?;

    if existing.0 {
        return Err(ApiError::Conflict("domain already exists".into()));
    }

    // Look up the plan's max_sending_domains and the current domain count.
    let domain_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM domains WHERE tenant_id = $1")
        .bind(&auth.tenant_id)
        .fetch_one(&mut *tx)
        .await?;

    let max_domains: Option<(i64,)> = sqlx::query_as(
        r#"SELECT COALESCE((p.features->>'max_sending_domains')::bigint, -1)
           FROM tenants t JOIN plans p ON t.plan = p.name
           WHERE t.id = $1"#,
    )
    .bind(&auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((limit,)) = max_domains {
        // -1 means unlimited
        if limit >= 0 && domain_count >= limit {
            return Err(ApiError::Forbidden(format!(
                "domain limit reached: your plan allows {} sending domain{}",
                limit,
                if limit == 1 { "" } else { "s" }
            )));
        }
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let selector = new_dkim_selector();
    let key_pair = generate_dkim_keypair().map_err(dkim_key_provisioning_error)?;
    let key_aad = dkim_private_key_aad(&auth.tenant_id, &id.to_string());
    let encrypted_private_key = encrypt_dkim_private_key(&key_pair.private_key_pem, &key_aad)
        .map_err(dkim_key_provisioning_error)?;

    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified,
         return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, dkim_selector,
         dkim_public_key, dkim_private_key, dkim_enabled, ses_verified, verified, created_at, updated_at)
         VALUES ($1,$2,$3,'pending',false,false,false,false,false,false,false,$4,$5,$6,true,false,false,$7,$7)",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&domain_name)
    .bind(&selector)
    .bind(&key_pair.public_key)
    .bind(&encrypted_private_key)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        if domain_name_conflict(&error) {
            ApiError::Conflict("domain already exists or is already claimed".into())
        } else {
            error.into()
        }
    })?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(DomainResponse {
            id: id.to_string(),
            name: domain_name,
            status: "pending".into(),
            ses_verified: false,
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
        "SELECT id::text AS id, name, status, ses_verified, spf_verified, dkim_verified, dmarc_verified, return_path_verified, created_at
         FROM domains WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(clamp_limit(params.limit, 200))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<DomainResponse>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;

    let row = sqlx::query_as::<_, DomainRow>(
        "SELECT id::text AS id, name, status, ses_verified, spf_verified, dkim_verified, dmarc_verified, return_path_verified, created_at
         FROM domains WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;

    Ok(Json(row.into()))
}

async fn delete_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["domains:write"])?;

    let mut tx = state.db.begin().await?;
    lock_tenant_domain_mutations(&mut tx, &auth.tenant_id).await?;

    // Lock the row and the globally scoped SES identity before touching either
    // resource. A delete cannot then race a re-create of the same domain name.
    let domain: Option<(String, bool)> =
        sqlx::query_as("SELECT name, ses_verified FROM domains WHERE id = $1::uuid AND tenant_id = $2 FOR UPDATE")
            .bind(&id)
            .bind(&auth.tenant_id)
            .fetch_optional(&mut *tx)
            .await?;

    let (domain_name, ses_verified) = domain
        .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;
    lock_domain_identity(&mut tx, &domain_name).await?;

    // If SES actually accepted this identity for sending, remove it before the
    // local row is released for a future create/verify cycle. Pending legacy
    // identities are safely reconfigured by verification if the name returns.
    if Config::ses_transport_enabled() && ses_verified {
        delete_ses_domain_identity(&state, &domain_name).await?;
    }

    let result = sqlx::query("DELETE FROM domains WHERE id = $1::uuid AND tenant_id = $2")
        .bind(&id)
        .bind(&auth.tenant_id)
        .execute(&mut *tx)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn verify_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<VerifyResponse>, ApiError> {
    require_scopes(&auth, &["domains:write"])?;

    verify_domain_for_tenant(&state, &auth.tenant_id, &id).await
}

/// Verify a domain using the same locked DNS, DKIM, and SES readiness path as
/// the customer endpoint. Internal platform-sender operations call this after
/// their separate administrative authorization check.
pub(crate) async fn verify_domain_for_tenant(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<Json<VerifyResponse>, ApiError> {

        let mut tx = state.db.begin().await?;
        lock_tenant_domain_mutations(&mut tx, tenant_id).await?;

        let row = sqlx::query_as::<_, DomainFullRow>(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, name, dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled
            FROM domains WHERE id = $1::uuid AND tenant_id = $2 FOR UPDATE",
    )
    .bind(&id)
    .bind(tenant_id)
        .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;
        lock_domain_identity(&mut tx, &row.name).await?;

    // Legacy rows may predate per-domain keys. This explicit mutating endpoint
    // is the only place that provisions or repairs them; GET endpoints never
    // create key material behind the customer's back.
        let dkim_material = ensure_domain_dkim_material(&mut tx, &row).await?;

    // Perform real DNS lookups
    let dns = DNS_LOOKUP.as_ref().map_err(|e| {
        tracing::error!(error = %e, "DNS resolver initialization failed");
        ApiError::ServiceUnavailable("DNS verification is temporarily unavailable".into())
    })?;

    let ses_transport = Config::ses_transport_enabled();
    let return_path_hostname = return_path_hostname(&row.name);
    let (spf, return_path) = if ses_transport {
        // SES custom MAIL FROM requires this SPF record at the bounce
        // subdomain, not a fictional ApexMail-owned include host at the apex.
        let spf = match dns.lookup_spf(&return_path_hostname).await {
            Ok(Some(spf_record)) => spf_record
                .raw
                .split_whitespace()
                .any(|token| token.eq_ignore_ascii_case(SPF_INCLUDE_MECHANISM)),
            Ok(None) => false,
            Err(e) => {
                warn!("SPF lookup failed for {}: {}", return_path_hostname, e);
                false
            }
        };

        let return_path_mx_target = return_path_mx_target(&state.config.aws_region);
        let return_path = match dns.lookup_mx(&return_path_hostname).await {
            Ok(records) => records.iter().any(|record| {
                record.priority == SES_RETURN_PATH_MX_PRIORITY
                    && dns_target_matches(&record.exchange, &return_path_mx_target)
            }),
            Err(e) => {
                warn!("MAIL FROM MX lookup failed for {}: {}", return_path_hostname, e);
                false
            }
        };
        (spf, return_path)
    } else {
        (false, false)
    };

    // A syntactically valid DKIM TXT record is not enough: it must publish the
    // exact public key belonging to the private key we will use to sign.
    let dkim = match dns.lookup_dkim(&dkim_material.selector, &row.name).await {
        Ok(Some(record)) => {
            record.version.as_deref() == Some("DKIM1")
                && record.key_type.eq_ignore_ascii_case("rsa")
                && dkim_public_keys_match(&dkim_material.public_key, &record.public_key)
        }
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

    let local_ready = sender_dns_is_ready(spf, dkim, dmarc, return_path, ses_transport);

    // SES verification is asynchronous. Treat a successful API request as
    // pending and use GetEmailIdentity's actual state before authorizing SES
    // delivery. SMTP deployments use the same DNS/key pair but do not require
    // an SES identity.
    let ses_verified = if local_ready && ses_transport {
        match configure_ses_domain_identity(
            &state,
            &row.name,
            &dkim_material.selector,
            &dkim_material.private_key_pem,
        )
        .await
        {
            Ok(ready) => ready,
            Err(error) => {
                warn!(domain = %row.name, error = %error, "SES domain identity remains pending");
                false
            }
        }
    } else {
        false
    };

    let status = if local_ready && (!ses_transport || ses_verified) {
        "verified"
    } else {
        "pending"
    };

    sqlx::query(
        "UPDATE domains SET spf_verified=$1, dkim_verified=$2, dmarc_verified=$3,
         return_path_verified=$4, status=$5, ses_verified=$6, verified=$7, dkim_enabled=true,
         updated_at=NOW() WHERE id=$8::uuid AND tenant_id=$9",
    )
    .bind(spf)
    .bind(dkim)
    .bind(dmarc)
    .bind(return_path)
    .bind(status)
    .bind(ses_verified)
    .bind(status == "verified")
    .bind(&id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // SCALE-M-05: Invalidate cached domain data on verification status change
    let cache_key = format!("apexmail:cache:domain:{}", id);
    if let Err(e) = cache_del(&state.redis, &cache_key).await {
        warn!(error = %e, domain_id = %id, "failed to invalidate domain cache after verification");
    }

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
    Path(id): Path<String>,
) -> Result<Json<DnsRecordsResponse>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;

    let row = sqlx::query_as::<_, DomainFullRow>(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, name, dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled
         FROM domains WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;

    let selector = effective_dkim_selector(row.dkim_selector.as_deref()).to_string();
    let public_key = row
        .dkim_public_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())
        .filter(|_| {
            row.dkim_private_key
                .as_deref()
                .is_some_and(|key| !key.trim().is_empty())
        })
        .ok_or_else(|| {
            ApiError::Conflict(
                "domain DKIM material is incomplete; call POST /v1/domains/:id/verify to provision it"
                    .into(),
            )
        })?;

    let records = required_sender_dns_records(
        &row.name,
        &selector,
        public_key,
        &state.config.aws_region,
        Config::ses_transport_enabled(),
    );

    Ok(Json(DnsRecordsResponse {
        domain: row.name,
        records,
    }))
}

struct DomainDkimMaterial {
    selector: String,
    public_key: String,
    private_key_pem: zeroize::Zeroizing<String>,
}

/// Safe operational view of the platform sender. It deliberately excludes the
/// private key while making the exact DNS records available to an operator.
#[derive(Debug, Serialize)]
pub struct SystemSenderStatus {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub ready: bool,
    pub records: Vec<DnsRecord>,
}

#[derive(sqlx::FromRow)]
struct SystemSenderStatusRow {
    id: String,
    name: String,
    status: String,
    dkim_selector: Option<String>,
    dkim_public_key: Option<String>,
}

/// Return the platform sender's current readiness and, after provisioning,
/// the exact per-domain records that must be published. This function never
/// exposes private material and never promotes readiness by itself.
pub(crate) async fn system_sender_status(
    state: &AppState,
) -> Result<SystemSenderStatus, ApiError> {
    let row = sqlx::query_as::<_, SystemSenderStatusRow>(
        "SELECT id::text AS id, name, status, dkim_selector, dkim_public_key
         FROM domains WHERE tenant_id = $1 AND name = $2",
    )
    .bind(SYSTEM_TENANT_ID)
    .bind(SYSTEM_DOMAIN)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        ApiError::ServiceUnavailable(
            "system sender is absent; run the system-sender bootstrap operation".into(),
        )
    })?;

    let records = match (
        row.dkim_selector.as_deref().filter(|value| is_valid_dkim_selector(value)),
        row.dkim_public_key
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
    ) {
        (Some(selector), Some(public_key)) => required_sender_dns_records(
            &row.name,
            selector,
            public_key,
            &state.config.aws_region,
            Config::ses_transport_enabled(),
        ),
        _ => Vec::new(),
    };

    let ready = crate::routes::system_sender::ensure_system_sender_ready(&state.db)
        .await
        .is_ok();

    Ok(SystemSenderStatus {
        id: row.id,
        domain: row.name,
        status: row.status,
        ready,
        records,
    })
}

/// Ensure that the fixed platform tenant/domain exists and has encrypted
/// per-domain DKIM material. It is safe to invoke on every deployment: valid
/// material is preserved, while absent, malformed, or legacy plaintext data is
/// repaired and left pending for explicit DNS/SES verification.
pub async fn bootstrap_system_sender(
    state: &AppState,
) -> Result<SystemSenderStatus, ApiError> {
    let mut tx = state.db.begin().await?;
    lock_tenant_domain_mutations(&mut tx, SYSTEM_TENANT_ID).await?;
    lock_domain_identity(&mut tx, SYSTEM_DOMAIN).await?;

    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
         VALUES ($1, 'ApexMail System', 'system', 'enterprise', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
         ON CONFLICT DO NOTHING",
    )
    .bind(SYSTEM_TENANT_ID)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO domains (
            id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified,
            return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified,
            dkim_enabled, ses_verified, verified, created_at, updated_at
         ) VALUES (
            $1::uuid, $2, $3, 'pending', false, false, false,
            false, false, false, false, false, false, false, NOW(), NOW()
         ) ON CONFLICT DO NOTHING",
    )
    .bind(SYSTEM_DOMAIN_ID)
    .bind(SYSTEM_TENANT_ID)
    .bind(SYSTEM_DOMAIN)
    .execute(&mut *tx)
    .await?;

    let row = sqlx::query_as::<_, DomainFullRow>(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, name, dkim_selector,
                dkim_public_key, dkim_private_key, dkim_enabled
         FROM domains
            WHERE tenant_id = $1 AND name = $2
         FOR UPDATE",
    )
    .bind(SYSTEM_TENANT_ID)
    .bind(SYSTEM_DOMAIN)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        ApiError::Conflict(
            "the platform sender domain is owned by a different domain record".into(),
        )
    })?;

    ensure_domain_dkim_material(&mut tx, &row).await?;
    tx.commit().await?;

    system_sender_status(state).await
}

/// Ensure an explicit verification request has complete, coherent per-domain
/// DKIM material. Any partial or mismatched legacy state is replaced with a
/// new key pair and returned to pending status rather than risking signatures
/// that cannot validate against the displayed DNS record.
async fn ensure_domain_dkim_material(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &DomainFullRow,
) -> Result<DomainDkimMaterial, ApiError> {
    let valid_selector = row
        .dkim_selector
        .as_deref()
        .filter(|selector| is_valid_dkim_selector(selector));
    let existing_public_key = row
        .dkim_public_key
        .as_deref()
        .filter(|key| !key.trim().is_empty());
    let existing_private_key = row
        .dkim_private_key
        .as_deref()
        .filter(|key| !key.trim().is_empty());

    if let (Some(selector), Some(public_key), Some(stored_private_key)) =
        (valid_selector, existing_public_key, existing_private_key)
    {
        let aad = dkim_private_key_aad(&row.tenant_id, &row.id);
        let private_key_pem = decrypt_dkim_private_key(stored_private_key, &aad)
            .map_err(dkim_key_provisioning_error)?;

        if let Ok(canonical_public_key) = public_key_base64_from_private_key_pem(&private_key_pem)
        {
            if dkim_public_keys_match(public_key, &canonical_public_key) {
                let private_key_needs_encryption = !is_encrypted_dkim_private_key(stored_private_key);
                let public_key_needs_normalization = public_key != canonical_public_key;
                if private_key_needs_encryption || public_key_needs_normalization || !row.dkim_enabled {
                    let persisted_private_key = if private_key_needs_encryption {
                        encrypt_dkim_private_key(&private_key_pem, &aad)
                            .map_err(dkim_key_provisioning_error)?
                    } else {
                        stored_private_key.to_string()
                    };
                    sqlx::query(
                        "UPDATE domains SET dkim_public_key=$1, dkim_private_key=$2, dkim_enabled=true,
                         updated_at=NOW() WHERE id=$3::uuid AND tenant_id=$4",
                    )
                    .bind(&canonical_public_key)
                    .bind(&persisted_private_key)
                    .bind(&row.id)
                    .bind(&row.tenant_id)
                    .execute(&mut **tx)
                    .await?;
                }

                return Ok(DomainDkimMaterial {
                    selector: selector.to_string(),
                    public_key: canonical_public_key,
                    private_key_pem,
                });
            }
        }
    }

    let selector = new_dkim_selector();
    let key_pair = generate_dkim_keypair().map_err(dkim_key_provisioning_error)?;
    let aad = dkim_private_key_aad(&row.tenant_id, &row.id);
    let encrypted_private_key = encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
        .map_err(dkim_key_provisioning_error)?;

    sqlx::query(
        "UPDATE domains SET dkim_selector=$1, dkim_public_key=$2, dkim_private_key=$3, dkim_enabled=true,
         dkim_verified=false, ses_verified=false, status='pending', verified=false, updated_at=NOW()
         WHERE id=$4::uuid AND tenant_id=$5",
    )
    .bind(&selector)
    .bind(&key_pair.public_key)
    .bind(&encrypted_private_key)
    .bind(&row.id)
    .bind(&row.tenant_id)
    .execute(&mut **tx)
    .await?;

    info!(domain = %row.name, selector, "provisioned a new per-domain DKIM key pair");
    Ok(DomainDkimMaterial {
        selector,
        public_key: key_pair.public_key,
        private_key_pem: key_pair.private_key_pem,
    })
}

fn is_valid_dkim_selector(selector: &str) -> bool {
    let selector = selector.trim();
    !selector.is_empty()
        && selector.len() <= 63
        && !selector.starts_with('-')
        && !selector.ends_with('-')
        && selector
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

// ─── SES identity management ───────────────────────────────────

/// Configure a domain identity for SES BYODKIM and return whether SES reports
/// it fully usable for sending. Creation/configuration success is deliberately
/// not treated as verification because SES checks DNS asynchronously.
async fn configure_ses_domain_identity(
    state: &AppState,
    domain: &str,
    selector: &str,
    private_key_pem: &str,
) -> Result<bool, ApiError> {
    let region = aws_sdk_sesv2::config::Region::new(state.config.aws_region.clone());
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let client = aws_sdk_sesv2::Client::new(&sdk_config);

    let ses_private_key = ses_private_key_base64_from_pem(private_key_pem)
        .map_err(dkim_key_provisioning_error)?;
    let dkim_attrs = DkimSigningAttributes::builder()
        .domain_signing_selector(selector)
        .domain_signing_private_key(&ses_private_key)
        .build();

    let result = client
        .create_email_identity()
        .email_identity(domain)
        .dkim_signing_attributes(dkim_attrs)
        .set_configuration_set_name(
            state
                .config
                .ses_configuration_set
                .as_deref()
                .filter(|name| !name.trim().is_empty())
                .map(str::to_owned),
        )
        .send()
        .await;

    match result {
        Ok(_) => info!(domain = %domain, selector, "SES BYODKIM identity creation requested"),
        Err(e) => {
            let msg = format!("{e}");
            if is_ses_identity_already_present(&msg) {
                // Existing identities may have been created as Easy DKIM.
                // Explicitly replace that configuration with this domain's
                // externally managed selector/private key pair.
                client
                    .put_email_identity_dkim_signing_attributes()
                    .email_identity(domain)
                    .signing_attributes_origin(DkimSigningAttributesOrigin::External)
                    .signing_attributes(
                        DkimSigningAttributes::builder()
                            .domain_signing_selector(selector)
                            .domain_signing_private_key(&ses_private_key)
                            .build(),
                    )
                    .send()
                    .await
                    .map_err(|error| {
                        warn!(domain, error = %error, "failed to configure existing SES identity for BYODKIM");
                        ApiError::ServiceUnavailable(
                            "SES DKIM configuration is temporarily unavailable; please retry shortly"
                                .into(),
                        )
                    })?;
                info!(domain = %domain, selector, "existing SES identity configured for BYODKIM");
            } else {
                tracing::error!(domain = %domain, error = %msg, "SES CreateEmailIdentity failed");
                return Err(ApiError::ServiceUnavailable(
                    "email identity creation failed — please retry or contact support".into(),
                ));
            }
        }
    };

    // Never let SES silently fall back to an amazonses.com MAIL FROM domain:
    // the exact MX/TXT pair returned by /dns-records must be usable first.
    client
        .put_email_identity_mail_from_attributes()
        .email_identity(domain)
        .mail_from_domain(return_path_hostname(domain))
        .behavior_on_mx_failure(BehaviorOnMxFailure::RejectMessage)
        .send()
        .await
        .map_err(|error| {
            warn!(domain, error = %error, "failed to configure SES custom MAIL FROM domain");
            ApiError::ServiceUnavailable(
                "SES MAIL FROM configuration is temporarily unavailable; please retry shortly".into(),
            )
        })?;

    let identity = client
        .get_email_identity()
        .email_identity(domain)
        .send()
        .await
        .map_err(|error| {
            warn!(domain, error = %error, "failed to read SES identity readiness");
            ApiError::ServiceUnavailable(
                "SES identity verification is temporarily unavailable; please retry shortly".into(),
            )
        })?;

    Ok(ses_identity_is_ready(
        &identity,
        &return_path_hostname(domain),
    ))
}

fn is_ses_identity_already_present(error_message: &str) -> bool {
    error_message.contains("AlreadyExistsException")
        || error_message.contains("ConflictException")
        || error_message.to_ascii_lowercase().contains("already exists")
}

fn ses_identity_is_ready(
    identity: &aws_sdk_sesv2::operation::get_email_identity::GetEmailIdentityOutput,
    expected_mail_from_domain: &str,
) -> bool {
    let dkim_ready = identity.dkim_attributes().is_some_and(|attributes| {
        attributes.signing_attributes_origin() == Some(&DkimSigningAttributesOrigin::External)
            && attributes.signing_enabled()
            && attributes.status() == Some(&DkimStatus::Success)
    });
    let mail_from_ready = identity.mail_from_attributes().is_some_and(|attributes| {
        attributes
            .mail_from_domain()
            .eq_ignore_ascii_case(expected_mail_from_domain)
            && attributes.mail_from_domain_status() == &MailFromDomainStatus::Success
    });

    identity.verified_for_sending_status()
        && identity.verification_status() == Some(&VerificationStatus::Success)
        && dkim_ready
        && mail_from_ready
}

/// Delete a domain identity from SES before releasing the local domain name.
async fn delete_ses_domain_identity(state: &AppState, domain: &str) -> Result<(), ApiError> {
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
        Ok(_) => {
            info!(domain = %domain, "SES email identity deleted");
            Ok(())
        }
        Err(error) => {
            let message = error.to_string();
            if message.contains("NotFoundException") || message.to_ascii_lowercase().contains("not found") {
                info!(domain = %domain, "SES email identity was already absent");
                Ok(())
            } else {
                warn!(domain = %domain, error = %error, "failed to delete SES email identity");
                Err(ApiError::ServiceUnavailable(
                    "SES identity cleanup is temporarily unavailable; retry deletion shortly".into(),
                ))
            }
        }
    }
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DomainRow {
    id: String,
    name: String,
    status: String,
    ses_verified: bool,
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
            ses_verified: r.ses_verified,
            spf_verified: r.spf_verified,
            dkim_verified: r.dkim_verified,
            dmarc_verified: r.dmarc_verified,
            return_path_verified: r.return_path_verified,
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct DomainFullRow {
    id: String,
    tenant_id: String,
    name: String,
    dkim_selector: Option<String>,
    dkim_public_key: Option<String>,
    dkim_private_key: Option<String>,
    dkim_enabled: bool,
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
        let records = vec![DnsRecord {
            record_type: "TXT".into(),
            hostname: "bounce.example.com".into(),
            value: SPF_RECORD_VALUE.into(),
            priority: None,
        }];
        let json = serde_json::to_value(&records).unwrap();
        assert_eq!(json[0]["record_type"], "TXT");
    }

    #[test]
    fn effective_dkim_selector_preserves_domain_assignment() {
        assert_eq!(
            effective_dkim_selector(Some("customer-2026")),
            "customer-2026"
        );
        assert_eq!(effective_dkim_selector(None), DEFAULT_DKIM_SELECTOR);
        assert_eq!(effective_dkim_selector(Some("   ")), DEFAULT_DKIM_SELECTOR);
    }

    #[test]
    fn return_path_record_matches_dashboard_instruction() {
        assert_eq!(return_path_hostname("example.com"), "bounce.example.com");
        let target = return_path_mx_target("eu-west-1");
        assert!(dns_target_matches(
            "feedback-smtp.eu-west-1.amazonses.com.",
            &target
        ));
        assert!(!dns_target_matches(
            "feedback-smtp.eu-west-1.amazonses.com.evil.com",
            &target
        ));
    }

    #[test]
    fn generated_selector_is_a_valid_dns_label() {
        assert!(is_valid_dkim_selector(&new_dkim_selector()));
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
    /// Human-readable, copy-pasteable remediation hint shown when the check
    /// fails. Powers the in-app "self-debug" UX (`expected → actual → fix
    /// here`) so customers do not need to open a support ticket for the
    /// common misconfigurations. See `docs/user-guide/troubleshooting.md`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DomainAuthRow {
    id: String,
    name: Option<String>,
    spf_verified: Option<bool>,
    dkim_verified: Option<bool>,
    dmarc_verified: Option<bool>,
    return_path_verified: Option<bool>,
    dkim_selector: Option<String>,
    dkim_public_key: Option<String>,
}

async fn get_auth_status(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<DomainAuthStatus>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;

    let domain = sqlx::query_as::<_, DomainAuthRow>(
        "SELECT id::text AS id, name, spf_verified, dkim_verified, dmarc_verified, return_path_verified, dkim_selector, dkim_public_key
         FROM domains WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(id.to_string())
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;

    let domain_name = domain.name.as_deref().unwrap_or(&domain.id);
    let selector = effective_dkim_selector(domain.dkim_selector.as_deref());
    let public_key = domain
        .dkim_public_key
        .as_deref()
        .filter(|key| !key.trim().is_empty());

    // Self-debug helper: populate `expected` + `fix` hints so the response
    // is actionable without a support ticket. The DKIM selector and
    // return-path values deliberately derive from the same record builders as
    // `/dns-records`; a domain-specific selector must never receive generic
    // remediation instructions.
    let check = |kind: AuthKind, verified: bool| -> AuthCheckResult {
        let expected = kind.expected(domain_name, selector, public_key, &state.config.aws_region);
        if verified {
            AuthCheckResult {
                status: "pass".into(),
                value: None,
                expected,
                fix: None,
            }
        } else {
            AuthCheckResult {
                status: "fail".into(),
                value: None,
                expected,
                fix: Some(kind.fix_hint(
                    domain_name,
                    selector,
                    public_key,
                    &state.config.aws_region,
                )),
            }
        }
    };

    let ses_transport = Config::ses_transport_enabled();
    let spf = domain.spf_verified.unwrap_or(false);
    let dkim = domain.dkim_verified.unwrap_or(false);
    let dmarc = domain.dmarc_verified.unwrap_or(false);
    let return_path = domain.return_path_verified.unwrap_or(false);

    // The TXT/MX custom MAIL FROM pair is part of the outbound SES contract;
    // a generic inbound MX record is not required for sending and should not
    // be presented as an ApexMail-hosted service requirement.
    let all_pass = sender_dns_is_ready(spf, dkim, dmarc, return_path, ses_transport);
    let any_pass = dkim || (ses_transport && spf);
    let not_required = || AuthCheckResult {
        status: "not_required".into(),
        value: None,
        expected: None,
        fix: None,
    };

    Ok(Json(DomainAuthStatus {
        domain: domain_name.into(),
        spf: if ses_transport {
            check(AuthKind::Spf, spf)
        } else {
            not_required()
        },
        dkim: check(AuthKind::Dkim, dkim),
        dmarc: check(AuthKind::Dmarc, dmarc),
        mx: AuthCheckResult {
            status: "not_required".into(),
            value: None,
            expected: None,
            fix: None,
        },
        return_path: if ses_transport {
            check(AuthKind::ReturnPath, return_path)
        } else {
            not_required()
        },
        overall_status: if all_pass {
            "authenticated".into()
        } else if any_pass {
            "partial".into()
        } else {
            "unauthenticated".into()
        },
    }))
}

/// The sending-authentication checks and mail-routing diagnostics
/// surfaced by `/auth-status`.
///
/// Each variant exposes a canonical `expected` record and a copy-pasteable
/// `fix_hint`. Centralising these strings here means the in-app dashboard,
/// the chatbot, the troubleshooting docs, and the API response stay in
/// lockstep — the chatbot answers SPF questions by quoting the same string
/// the API returns, so customers never see two different "fixes" for one
/// misconfiguration.
#[derive(Debug, Clone, Copy)]
enum AuthKind {
    Spf,
    Dkim,
    Dmarc,
    ReturnPath,
}

impl AuthKind {
    fn expected(
        self,
        domain: &str,
        selector: &str,
        public_key: Option<&str>,
        aws_region: &str,
    ) -> Option<String> {
        match self {
            AuthKind::Spf => {
                let record = return_path_spf_dns_record(domain);
                Some(format!("{} {}  {}", record.record_type, record.hostname, record.value))
            }
            AuthKind::Dkim => public_key.map(|public_key| {
                let record = dkim_dns_record(selector, domain, public_key);
                format!("{} {}  {}", record.record_type, record.hostname, record.value)
            }),
            AuthKind::Dmarc => Some(format!("TXT _dmarc.{domain}  {DMARC_RECORD_VALUE}")),
            AuthKind::ReturnPath => {
                let record = return_path_dns_record(domain, aws_region);
                Some(format!(
                    "{} {} {}  {}",
                    record.record_type,
                    record.priority.unwrap_or_default(),
                    record.hostname,
                    record.value
                ))
            }
        }
    }

    fn fix_hint(
        self,
        domain: &str,
        selector: &str,
        public_key: Option<&str>,
        aws_region: &str,
    ) -> String {
        match self {
            AuthKind::Spf => {
                let record = return_path_spf_dns_record(domain);
                format!(
                    "Custom MAIL FROM SPF is misconfigured. Add a TXT record at host `{}` with \
                     value `{}`. Do not add a second SPF record at this hostname; merge this \
                     mechanism into an existing record if needed, then re-verify.",
                    record.hostname, record.value
                )
            }
            AuthKind::Dkim => {
                match public_key {
                    Some(public_key) => {
                        let record = dkim_dns_record(selector, domain, public_key);
                        format!(
                            "DKIM is misconfigured. Add a TXT record at host `{}` with value \
                             `{}`. Preserve the complete `p=` value, wait for DNS propagation, \
                             then re-verify.",
                            record.hostname, record.value
                        )
                    }
                    None => "DKIM key material is incomplete. Call POST /v1/domains/:id/verify \
                             to provision a new per-domain key before publishing DNS."
                        .into(),
                }
            }
            AuthKind::Dmarc => {
                "DMARC missing. Add a TXT record at host `_dmarc` with value \
                 `v=DMARC1; p=quarantine; rua=mailto:dmarc@apexmail.io`. Start with \
                 `p=none` if you want monitoring before enforcement."
                    .into()
            }
            AuthKind::ReturnPath => {
                let record = return_path_dns_record(domain, aws_region);
                format!(
                    "Return-Path / bounce subdomain not configured. Add an MX record at host \
                     `{}` with priority {} pointing to `{}`. This improves SPF alignment and \
                     bounce processing.",
                    record.hostname,
                    record.priority.unwrap_or_default(),
                    record.value
                )
            }
        }
    }
}

#[cfg(test)]
mod tests_auth {
    use super::*;

    #[test]
    fn test_domain_response_serialisation() {
        let resp = DomainResponse {
            id: String::new(),
            name: "example.com".into(),
            status: "verified".into(),
            ses_verified: true,
            spf_verified: true,
            dkim_verified: true,
            dmarc_verified: true,
            return_path_verified: false,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["spf_verified"], true);
    }

    #[test]
    fn auth_kind_fix_hints_are_actionable() {
        // Self-debug contract: every failing check must surface (a) a canonical
        // `expected` record and (b) a copy-pasteable `fix_hint` so customers can
        // remediate without contacting support.
        for kind in [
            AuthKind::Spf,
            AuthKind::Dkim,
            AuthKind::Dmarc,
            AuthKind::ReturnPath,
        ] {
            let expected = kind
                .expected(
                    "example.com",
                    "customer-2026",
                    Some("MIIBIjAN"),
                    "eu-west-1",
                )
                .expect("provisioned checks must expose a DNS record");
            let fix = kind.fix_hint(
                "example.com",
                "customer-2026",
                Some("MIIBIjAN"),
                "eu-west-1",
            );
            assert!(!expected.is_empty(), "expected string must not be empty");
            assert!(fix.len() > 40, "fix hint must be substantive: {fix}");
        }
        // SPF hint must actually mention the canonical include token, which is
        // what the chatbot/mailbot training data quotes verbatim.
        assert!(AuthKind::Spf
            .fix_hint("example.com", "customer-2026", Some("MIIBIjAN"), "eu-west-1")
            .contains("include:amazonses.com"));
        // DMARC hint must reference the policy directive we recommend.
        assert!(AuthKind::Dmarc
            .fix_hint("example.com", "customer-2026", Some("MIIBIjAN"), "eu-west-1")
            .contains("p=quarantine"));
    }

    #[test]
    fn auth_status_uses_the_same_assigned_records_as_dns_records() {
        let domain = "example.com";
        let selector = "customer-2026";

        assert_eq!(
            AuthKind::Dkim.expected(domain, selector, Some("MIIBIjAN"), "eu-west-1"),
            Some("TXT customer-2026._domainkey.example.com  v=DKIM1; k=rsa; p=MIIBIjAN".into())
        );
        assert_eq!(
            AuthKind::ReturnPath.expected(domain, selector, Some("MIIBIjAN"), "eu-west-1"),
            Some("MX 10 bounce.example.com  feedback-smtp.eu-west-1.amazonses.com".into())
        );
        assert!(AuthKind::Dkim
            .fix_hint(domain, selector, Some("MIIBIjAN"), "eu-west-1")
            .contains("customer-2026._domainkey.example.com"));
        assert!(AuthKind::ReturnPath
            .fix_hint(domain, selector, Some("MIIBIjAN"), "eu-west-1")
            .contains("feedback-smtp.eu-west-1.amazonses.com"));
    }

    #[test]
    fn auth_check_result_skips_fix_when_passing() {
        let r = AuthCheckResult {
            status: "pass".into(),
            value: None,
            expected: Some("x".into()),
            fix: None,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("fix").is_none(), "fix omitted on pass");
    }

    #[test]
    fn ses_readiness_requires_verified_byodkim_and_custom_mail_from() {
        let dkim = aws_sdk_sesv2::types::DkimAttributes::builder()
            .signing_enabled(true)
            .status(DkimStatus::Success)
            .signing_attributes_origin(DkimSigningAttributesOrigin::External)
            .build();
        let mail_from = aws_sdk_sesv2::types::MailFromAttributes::builder()
            .mail_from_domain("bounce.example.com")
            .mail_from_domain_status(MailFromDomainStatus::Success)
            .behavior_on_mx_failure(BehaviorOnMxFailure::RejectMessage)
            .build()
            .unwrap();
        let ready = aws_sdk_sesv2::operation::get_email_identity::GetEmailIdentityOutput::builder()
            .verified_for_sending_status(true)
            .verification_status(VerificationStatus::Success)
            .dkim_attributes(dkim)
            .mail_from_attributes(mail_from)
            .build();

        assert!(ses_identity_is_ready(&ready, "bounce.example.com"));
        assert!(!ses_identity_is_ready(&ready, "bounce.other.example"));

        let pending = aws_sdk_sesv2::operation::get_email_identity::GetEmailIdentityOutput::builder()
            .verified_for_sending_status(false)
            .verification_status(VerificationStatus::Success)
            .dkim_attributes(
                aws_sdk_sesv2::types::DkimAttributes::builder()
                    .signing_enabled(true)
                    .status(DkimStatus::Success)
                    .signing_attributes_origin(DkimSigningAttributesOrigin::External)
                    .build(),
            )
            .mail_from_attributes(
                aws_sdk_sesv2::types::MailFromAttributes::builder()
                    .mail_from_domain("bounce.example.com")
                    .mail_from_domain_status(MailFromDomainStatus::Success)
                    .behavior_on_mx_failure(BehaviorOnMxFailure::RejectMessage)
                    .build()
                    .unwrap(),
            )
            .build();
        assert!(!ses_identity_is_ready(&pending, "bounce.example.com"));
    }
}
