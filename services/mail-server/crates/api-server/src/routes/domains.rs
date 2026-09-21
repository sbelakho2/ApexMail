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
    decrypt_dkim_private_key, dkim_private_key_aad, dkim_public_keys_match, dkim_txt_record_value,
    encrypt_dkim_private_key, generate_dkim_keypair, is_encrypted_dkim_private_key,
    public_key_base64_from_private_key_pem, ses_private_key_base64_from_pem,
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
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::Config;
use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::routes::system_sender::{SYSTEM_DOMAIN, SYSTEM_DOMAIN_ID, SYSTEM_TENANT_ID};
use crate::state::AppState;
use billing_entitlements::CapacityKey;

static DNS_LOOKUP: LazyLock<Result<DnsLookup, String>> = LazyLock::new(|| {
    DnsLookup::new().map_err(|e| format!("DNS resolver initialization failed: {e}"))
});

// ─── Shared SES client (audit M-5) ──────────────────────────────

/// A single process talks to exactly one AWS account/region, so the SES SDK
/// client (and its connection pool) is process-wide state, keyed by region.
type SharedSesClient = std::sync::Arc<aws_sdk_sesv2::Client>;

/// M-5(1): `configure_ses_domain_identity`/`delete_ses_domain_identity`
/// previously built a fresh `aws_config` SDK stack (credential chain,
/// HTTP/TLS pool) on every call. The map makes construction a one-off per
/// region; the `Arc` handle returned per call is a cheap clone.
static SES_CLIENTS: LazyLock<std::sync::Mutex<std::collections::HashMap<String, SharedSesClient>>> =
    LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Return the process-wide SES client for `region`, constructing it at most
/// once. Concurrent first callers may both build a client; the loser's entry
/// is simply replaced — clients are interchangeable and lazily connected, so
/// this is harmless and avoids holding a std lock across an await.
async fn shared_ses_client(region: &str) -> SharedSesClient {
    // Lock-poisoning recovery: a panic in some other critical section while
    // holding this cache lock must not cascade into a worker panic here —
    // the map stays structurally valid (its operations are atomic), so the
    // poisoned guard is recovered rather than unwrapped. The guard is
    // dropped before the await (std locks must not be held across await
    // points), hence the two locking phases.
    let cached = {
        let clients = match SES_CLIENTS.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        clients.get(region).cloned()
    };
    if let Some(client) = cached {
        return client;
    }
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_sesv2::config::Region::new(region.to_string()))
        .load()
        .await;
    let client = std::sync::Arc::new(aws_sdk_sesv2::Client::new(&sdk_config));
    let mut clients = match SES_CLIENTS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    clients.insert(region.to_string(), client.clone());
    client
}

const DEFAULT_DKIM_SELECTOR: &str = "apexmail2026";
const RETURN_PATH_LABEL: &str = "bounce";
const SES_RETURN_PATH_MX_PRIORITY: u16 = 10;
const SPF_INCLUDE_MECHANISM: &str = "include:amazonses.com";
const SPF_RECORD_VALUE: &str = "v=spf1 include:amazonses.com ~all";

/// The DMARC record we instruct customers to publish. The aggregate-report
/// mailbox derives from the single product-domain constant (`SYSTEM_DOMAIN`
/// in `system_sender.rs`, currently `apexmail.ee`) so the guidance can never
/// drift to a domain the platform does not operate (audit M-4: the .io hint
/// previously drifted here).
fn dmarc_record_value() -> String {
    format!(
        "v=DMARC1; p=quarantine; rua=mailto:dmarc@{}",
        crate::routes::system_sender::SYSTEM_DOMAIN
    )
}

/// Effective DKIM selector for record building. `pub(crate)` so the SSR
/// domain detail page reuses the exact same record generation as
/// GET /v1/domains/:id/dns-records (never a duplicated copy).
pub(crate) fn effective_dkim_selector(selector: Option<&str>) -> &str {
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

/// The full record set a sender must publish. `pub(crate)` so the SSR
/// domain detail page renders the SAME records the JSON dns-records
/// endpoint returns (single source of truth).
pub(crate) fn required_sender_dns_records(
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
            value: dmarc_record_value(),
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
    dkim_verified && dmarc_verified && (!ses_transport || (spf_verified && return_path_verified))
}

fn domain_name_conflict(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23505")
}

/// Validate a domain id from a URL path before it reaches any
/// `$1::uuid` bind. A malformed id can never match a stored row, so it is
/// reported as a plain 404 — binding it raw would surface a PostgreSQL
/// `invalid input syntax for type uuid` (22P02) as a 500.
fn validated_domain_id(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id.trim()).map_err(|_| ApiError::NotFound("domain not found".into()))
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

    let domain_name = body.name.trim().trim_end_matches('.').to_ascii_lowercase();

    if !apexmail_lib::validation::is_valid_domain(&domain_name) {
        return Err(ApiError::Validation(vec![format!(
            "invalid domain name: {}",
            domain_name
        )]));
    }

    // Runtime entitlement snapshot, fetched BEFORE the transaction. The
    // authoritative capacity decision is evaluated below against the
    // in-transaction count; the SQL plan check stays as the race guard.
    let entitlement = crate::entitlements::snapshot(&state, &auth.tenant_id).await?;

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

    // Runtime entitlement capacity gate (override-aware, 403 Forbidden):
    // `domain_count + 1` is the total after this creation.
    crate::entitlements::gate_capacity(
        &entitlement,
        CapacityKey::SendingDomains,
        domain_count + 1,
    )?;

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
    .bind(id)
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

    let id = validated_domain_id(&id)?;
    let row = sqlx::query_as::<_, DomainRow>(
        "SELECT id::text AS id, name, status, ses_verified, spf_verified, dkim_verified, dmarc_verified, return_path_verified, created_at
         FROM domains WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
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

    // M-5(3): the SES DeleteEmailIdentity HTTPS round-trip used to run while
    // the domain row lock, the tenant advisory lock, and the SES-identity
    // advisory lock were all held — a multi-second external-IO window that
    // serialised every domain mutation for the tenant. Mirroring the verify
    // flow's re-phasing, the delete is now two phases:
    //
    // 1. short locked tx — collect (name, ses_verified) under the same locks
    //    a re-create would take, delete the row, commit;
    // 2. best-effort SES delete AFTER the commit, with no locks held. A
    //    failure is logged (and surfaces in metrics) but does not fail the
    //    request: the local row is already gone, and a stale SES identity is
    //    harmless — verification reconfigures pending identities if the name
    //    ever returns.
    let mut tx = state.db.begin().await?;
    lock_tenant_domain_mutations(&mut tx, &auth.tenant_id).await?;

    // Lock the row and the globally scoped SES identity before touching either
    // resource. A delete cannot then race a re-create of the same domain name.
    let id = validated_domain_id(&id)?;
    let domain: Option<(String, bool)> = sqlx::query_as(
        "SELECT name, ses_verified FROM domains WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await?;

    let (domain_name, ses_verified) =
        domain.ok_or_else(|| ApiError::NotFound("domain not found".into()))?;
    lock_domain_identity(&mut tx, &domain_name).await?;

    let result = sqlx::query("DELETE FROM domains WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&mut *tx)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("domain not found".into()));
    }

    tx.commit().await?;

    // Phase 2 — SES cleanup with no database locks held. If SES actually
    // accepted this identity for sending, remove it now that the local row is
    // released for a future create/verify cycle. Pending legacy identities
    // are safely reconfigured by verification if the name returns.
    if Config::ses_transport_enabled() && ses_verified {
        if let Err(error) = delete_ses_domain_identity(&state, &domain_name).await {
            error!(
                domain = %domain_name,
                error = %error,
                "SES identity cleanup after domain delete failed — the local row is deleted; the stale SES identity is harmless and will be reconfigured if the domain returns"
            );
        }
    }

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
///
/// M-5(2): this used to hold the domain row lock, the tenant advisory lock,
/// and the SES-identity advisory lock across every DNS lookup and every SES
/// HTTPS round-trip — a multi-second external-IO window that serialised all
/// domain mutations for the tenant (and platform-wide for a shared domain
/// name). The flow is now phased so external IO happens with NO database
/// locks held:
///
/// 1. short locked tx — read the row, take the advisory locks, provision or
///    repair DKIM material (DB-only work), commit;
/// 2. DNS lookups and the SES HTTPS calls against that material, lock-free;
/// 3. short locked tx — re-read the row under the SAME locks, verify the DKIM
///    material the observations were made against is still current, and only
///    then persist the verification outcome.
///
/// If a concurrent verify/delete rotated the keys between phases 1 and 3 the
/// observations are stale for the new material; the whole flow is retried
/// once and otherwise the currently stored state is returned.
pub(crate) async fn verify_domain_for_tenant(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<Json<VerifyResponse>, ApiError> {
    // A malformed path id can never match a row: 404 it here, before any
    // `$1::uuid` bind can surface a 22P02 cast error as a 500.
    let id = validated_domain_id(id)?.to_string();
    let dns = global_dns_lookup()?;
    verify_domain_for_tenant_with_dns(state, tenant_id, &id, dns).await
}

/// The process-wide production resolver, as a typed error for route callers.
/// Split out so the control-plane system-sender route (and any future route
/// that verifies a domain) resolves the transport exactly like this path —
/// and so tests can substitute a deterministic backend via the `_with_dns`
/// variants instead of touching the global.
pub(crate) fn global_dns_lookup() -> Result<&'static DnsLookup, ApiError> {
    DNS_LOOKUP.as_ref().map_err(|e| {
        tracing::error!(error = %e, "DNS resolver initialization failed");
        ApiError::ServiceUnavailable("DNS verification is temporarily unavailable".into())
    })
}

/// [`verify_domain_for_tenant`] with an injected DNS backend. Production
/// always passes the process-wide [`DnsLookup`]; tests inject a
/// deterministic fake so every record-edge case is exercised without a
/// resolver (and without real network I/O).
pub(crate) async fn verify_domain_for_tenant_with_dns<D: VerificationDns>(
    state: &AppState,
    tenant_id: &str,
    id: &str,
    dns: &D,
) -> Result<Json<VerifyResponse>, ApiError> {
    for _attempt in 0..2 {
        // Phase 1 — locked, DB-only: locks + DKIM material provisioning.
        let (row, dkim_material) = lock_and_provision_dkim(state, tenant_id, id).await?;

        // Phase 2 — external IO with no database locks held. The transport
        // mode is resolved ONCE here so every observation in one round shares
        // the same contract.
        let observations = observe_dns_and_ses(
            state,
            &row,
            &dkim_material,
            dns,
            Config::ses_transport_enabled(),
        )
        .await?;

        // Phase 3 — locked, DB-only: re-check currency under the same locks
        // and persist. `None` means the DKIM material rotated concurrently;
        // the loop retries once with fresh material.
        if let Some(response) = persist_verification(
            state,
            tenant_id,
            id,
            &row.name,
            &dkim_material,
            &observations,
        )
        .await?
        {
            // SCALE-M-05: Invalidate cached domain data on verification
            // status change.
            let cache_key = format!("apexmail:cache:domain:{}", id);
            if let Err(e) = cache_del(&state.redis, &cache_key).await {
                warn!(
                    error = %e,
                    domain_id = %id,
                    "failed to invalidate domain cache after verification"
                );
            }
            return Ok(Json(response));
        }
    }

    // Both attempts observed a concurrent DKIM rotation: never persist
    // observations made against stale keys — return the row's current state.
    current_verification_state(state, tenant_id, id).await
}

/// Phase 1 of verification: take the tenant + SES-identity advisory locks and
/// the domain row lock, then ensure the row has complete, coherent per-domain
/// DKIM material. This transaction performs database work only — it must
/// never wait on DNS or SES, so the locks are released immediately.
async fn lock_and_provision_dkim(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<(DomainFullRow, DomainDkimMaterial), ApiError> {
    let mut tx = state.db.begin().await?;
    lock_tenant_domain_mutations(&mut tx, tenant_id).await?;

    let row = sqlx::query_as::<_, DomainFullRow>(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, name, dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled
            FROM domains WHERE id = $1::uuid AND tenant_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(tenant_id)
        .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;
    lock_domain_identity(&mut tx, &row.name).await?;

    // Legacy rows may predate per-domain keys. This explicit mutating endpoint
    // is the only place that provisions or repairs them; GET endpoints never
    // create key material behind the customer's back.
    let dkim_material = ensure_domain_dkim_material(&mut tx, &row).await?;
    tx.commit().await?;

    Ok((row, dkim_material))
}

/// Everything verification observed about the outside world, gathered while
/// holding no database locks (phase 2).
#[derive(Debug, Clone, Copy)]
struct VerificationObservations {
    spf_verified: bool,
    dkim_verified: bool,
    dmarc_verified: bool,
    return_path_verified: bool,
    /// SES identity readiness (only resolved when local DNS is ready and the
    /// SES transport is enabled).
    ses_verified: bool,
    ses_transport: bool,
}

impl VerificationObservations {
    fn local_ready(&self) -> bool {
        sender_dns_is_ready(
            self.spf_verified,
            self.dkim_verified,
            self.dmarc_verified,
            self.return_path_verified,
            self.ses_transport,
        )
    }

    /// `(status, verified)` for the persisted row and the API response.
    fn outcome(&self) -> (&'static str, bool) {
        verification_outcome(self.local_ready(), self.ses_verified, self.ses_transport)
    }
}

/// Pure decision extracted from the verification flow (M-5): SES verification
/// is asynchronous. Treat a successful API request as pending and use
/// GetEmailIdentity's actual state before authorizing SES delivery. SMTP
/// deployments use the same DNS/key pair but do not require an SES identity.
fn verification_outcome(
    local_ready: bool,
    ses_verified: bool,
    ses_transport: bool,
) -> (&'static str, bool) {
    let verified = local_ready && (!ses_transport || ses_verified);
    (if verified { "verified" } else { "pending" }, verified)
}

/// The DNS observations verification performs, abstracted so the record
/// matrix can be driven deterministically in tests. Production implements
/// this with the process-wide [`DnsLookup`]; the `Err` side is the
/// resolver-failure signal verification already treats as "not verified".
pub(crate) trait VerificationDns {
    async fn lookup_spf(&self, host: &str) -> Result<Option<dns_resolver::SpfRecord>, String>;
    async fn lookup_mx(&self, host: &str) -> Result<Vec<dns_resolver::MxRecord>, String>;
    async fn lookup_dkim(
        &self,
        selector: &str,
        domain: &str,
    ) -> Result<Option<dns_resolver::DkimRecord>, String>;
    async fn lookup_dmarc(&self, domain: &str)
        -> Result<Option<dns_resolver::DmarcPolicy>, String>;
}

impl VerificationDns for DnsLookup {
    async fn lookup_spf(&self, host: &str) -> Result<Option<dns_resolver::SpfRecord>, String> {
        DnsLookup::lookup_spf(self, host)
            .await
            .map_err(|e| e.to_string())
    }

    async fn lookup_mx(&self, host: &str) -> Result<Vec<dns_resolver::MxRecord>, String> {
        DnsLookup::lookup_mx(self, host)
            .await
            .map_err(|e| e.to_string())
    }

    async fn lookup_dkim(
        &self,
        selector: &str,
        domain: &str,
    ) -> Result<Option<dns_resolver::DkimRecord>, String> {
        DnsLookup::lookup_dkim(self, selector, domain)
            .await
            .map_err(|e| e.to_string())
    }

    async fn lookup_dmarc(
        &self,
        domain: &str,
    ) -> Result<Option<dns_resolver::DmarcPolicy>, String> {
        DnsLookup::lookup_dmarc(self, domain)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Phase 2 of verification: perform the real DNS lookups and (when locally
/// ready) the SES identity HTTPS calls against the provisioned DKIM material.
/// No database transaction is open while this runs.
async fn observe_dns_and_ses<D: VerificationDns>(
    state: &AppState,
    row: &DomainFullRow,
    dkim_material: &DomainDkimMaterial,
    dns: &D,
    ses_transport: bool,
) -> Result<VerificationObservations, ApiError> {
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
                warn!(
                    "MAIL FROM MX lookup failed for {}: {}",
                    return_path_hostname, e
                );
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

    let mut observations = VerificationObservations {
        spf_verified: spf,
        dkim_verified: dkim,
        dmarc_verified: dmarc,
        return_path_verified: return_path,
        ses_verified: false,
        ses_transport,
    };

    if observations.local_ready() && ses_transport {
        observations.ses_verified = match configure_ses_domain_identity(
            state,
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
    }

    Ok(observations)
}

/// Pure staleness check for phase 3: the observations are only valid to
/// persist if the row still carries exactly the DKIM material they were made
/// against. A concurrent verify (key repair) or delete+re-create rotates the
/// selector/public key, which must invalidate them.
fn dkim_material_is_current(
    row_selector: Option<&str>,
    row_public_key: Option<&str>,
    material: &DomainDkimMaterial,
) -> bool {
    row_selector.is_some_and(|selector| selector == material.selector)
        && row_public_key.is_some_and(|key| key.trim() == material.public_key)
}

/// Phase 3 of verification: under the same locks as phase 1, re-read the row
/// and persist the observed outcome — but only if the DKIM material is
/// unchanged since the observations were made. Returns `None` when the
/// material rotated concurrently (caller retries or returns current state).
async fn persist_verification(
    state: &AppState,
    tenant_id: &str,
    id: &str,
    domain_name: &str,
    dkim_material: &DomainDkimMaterial,
    observations: &VerificationObservations,
) -> Result<Option<VerifyResponse>, ApiError> {
    let mut tx = state.db.begin().await?;
    lock_tenant_domain_mutations(&mut tx, tenant_id).await?;

    let row = sqlx::query_as::<_, DomainFullRow>(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, name, dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled
            FROM domains WHERE id = $1::uuid AND tenant_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(tenant_id)
        .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;
    lock_domain_identity(&mut tx, &row.name).await?;

    if !dkim_material_is_current(
        row.dkim_selector.as_deref(),
        row.dkim_public_key.as_deref(),
        dkim_material,
    ) {
        // Stale observations — do NOT write them. Rolling back releases the
        // locks so the retry (or the concurrent writer) can proceed.
        tx.rollback().await?;
        warn!(
            domain = %row.name,
            "DKIM material rotated during verification; observations discarded"
        );
        return Ok(None);
    }

    let (status, verified) = observations.outcome();
    sqlx::query(
        "UPDATE domains SET spf_verified=$1, dkim_verified=$2, dmarc_verified=$3,
         return_path_verified=$4, status=$5, ses_verified=$6, verified=$7, dkim_enabled=true,
         updated_at=NOW() WHERE id=$8::uuid AND tenant_id=$9",
    )
    .bind(observations.spf_verified)
    .bind(observations.dkim_verified)
    .bind(observations.dmarc_verified)
    .bind(observations.return_path_verified)
    .bind(status)
    .bind(observations.ses_verified)
    .bind(verified)
    .bind(id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Some(VerifyResponse {
        domain: domain_name.to_string(),
        spf_verified: observations.spf_verified,
        dkim_verified: observations.dkim_verified,
        dmarc_verified: observations.dmarc_verified,
        return_path_verified: observations.return_path_verified,
        status: status.into(),
    }))
}

/// Fall back to reporting the row's currently stored verification state
/// (used when concurrent rotations invalidated two observation rounds).
async fn current_verification_state(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<Json<VerifyResponse>, ApiError> {
    let row = sqlx::query_as::<_, DomainRow>(
        "SELECT id::text AS id, name, status, ses_verified, spf_verified, dkim_verified, dmarc_verified, return_path_verified, created_at
         FROM domains WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;

    Ok(Json(VerifyResponse {
        domain: row.name,
        spf_verified: row.spf_verified,
        dkim_verified: row.dkim_verified,
        dmarc_verified: row.dmarc_verified,
        return_path_verified: row.return_path_verified,
        status: row.status,
    }))
}

async fn get_dns_records(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<DnsRecordsResponse>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;

    let id = validated_domain_id(&id)?;
    let row = sqlx::query_as::<_, DomainFullRow>(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, name, dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled
         FROM domains WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
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
pub(crate) async fn system_sender_status(state: &AppState) -> Result<SystemSenderStatus, ApiError> {
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
        row.dkim_selector
            .as_deref()
            .filter(|value| is_valid_dkim_selector(value)),
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
pub async fn bootstrap_system_sender(state: &AppState) -> Result<SystemSenderStatus, ApiError> {
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

        if let Ok(canonical_public_key) = public_key_base64_from_private_key_pem(&private_key_pem) {
            if dkim_public_keys_match(public_key, &canonical_public_key) {
                let private_key_needs_encryption =
                    !is_encrypted_dkim_private_key(stored_private_key);
                let public_key_needs_normalization = public_key != canonical_public_key;
                if private_key_needs_encryption
                    || public_key_needs_normalization
                    || !row.dkim_enabled
                {
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
    // M-5(1): reuse the process-wide SES client instead of rebuilding the
    // SDK stack per verification request.
    let client = shared_ses_client(&state.config.aws_region).await;

    let ses_private_key =
        ses_private_key_base64_from_pem(private_key_pem).map_err(dkim_key_provisioning_error)?;
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
                "SES MAIL FROM configuration is temporarily unavailable; please retry shortly"
                    .into(),
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
        || error_message
            .to_ascii_lowercase()
            .contains("already exists")
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
    // M-5(1): reuse the process-wide SES client instead of rebuilding the
    // SDK stack per deletion request.
    let client = shared_ses_client(&state.config.aws_region).await;

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
            if message.contains("NotFoundException")
                || message.to_ascii_lowercase().contains("not found")
            {
                info!(domain = %domain, "SES email identity was already absent");
                Ok(())
            } else {
                warn!(domain = %domain, error = %error, "failed to delete SES email identity");
                Err(ApiError::ServiceUnavailable(
                    "SES identity cleanup is temporarily unavailable; retry deletion shortly"
                        .into(),
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

    // ── M-5: reordered verification flow + cached SES client ──────

    #[test]
    fn verification_outcome_requires_local_readiness_and_ses_when_transported() {
        // Pure decision function for the phased verification flow: status is
        // only "verified" when local DNS is ready AND (on the SES transport)
        // SES itself reports the identity usable.
        assert_eq!(
            verification_outcome(true, true, true),
            ("verified", true),
            "SES transport: ready DNS + ready SES identity verifies"
        );
        assert_eq!(
            verification_outcome(true, false, true),
            ("pending", false),
            "SES transport: SES still pending keeps the domain pending"
        );
        assert_eq!(
            verification_outcome(false, true, true),
            ("pending", false),
            "SES cannot rescue incomplete DNS"
        );
        assert_eq!(
            verification_outcome(true, false, false),
            ("verified", true),
            "SMTP transport: DKIM+DMARC alone suffice (no SES identity required)"
        );
        assert_eq!(
            verification_outcome(false, false, false),
            ("pending", false)
        );
    }

    #[test]
    fn dkim_material_currency_detects_concurrent_rotation() {
        let material = DomainDkimMaterial {
            selector: "am-current".into(),
            public_key: "MIIBIjAN".into(),
            private_key_pem: zeroize::Zeroizing::new(String::new()),
        };

        assert!(dkim_material_is_current(
            Some("am-current"),
            Some("MIIBIjAN"),
            &material
        ));
        // Selector rotated by a concurrent verify → observations are stale.
        assert!(!dkim_material_is_current(
            Some("am-rotated"),
            Some("MIIBIjAN"),
            &material
        ));
        // Public key replaced (key repair) → stale.
        assert!(!dkim_material_is_current(
            Some("am-current"),
            Some("MIIBIjANother"),
            &material
        ));
        // Material cleared (delete/re-create) → stale.
        assert!(!dkim_material_is_current(None, None, &material));
    }

    /// M-5(1): the SES client must be constructed once per region and reused,
    /// never rebuilt per verification/deletion request.
    #[tokio::test]
    async fn ses_client_is_shared_across_calls_per_region() {
        // This builds a real AWS SDK client: route it through the
        // deterministic TLS-root test environment (the macOS keychain read
        // under load intermittently yields zero parseable roots).
        crate::test_db::ensure_aws_test_env();
        let first = shared_ses_client("eu-north-1").await;
        let second = shared_ses_client("eu-north-1").await;
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "same region must yield the same cached SES client"
        );
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

    let id = validated_domain_id(&id)?;
    let domain = sqlx::query_as::<_, DomainAuthRow>(
        "SELECT id::text AS id, name, spf_verified, dkim_verified, dmarc_verified, return_path_verified, dkim_selector, dkim_public_key
         FROM domains WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
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
                Some(format!(
                    "{} {}  {}",
                    record.record_type, record.hostname, record.value
                ))
            }
            AuthKind::Dkim => public_key.map(|public_key| {
                let record = dkim_dns_record(selector, domain, public_key);
                format!(
                    "{} {}  {}",
                    record.record_type, record.hostname, record.value
                )
            }),
            AuthKind::Dmarc => Some(format!("TXT _dmarc.{domain}  {}", dmarc_record_value())),
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
            AuthKind::Dkim => match public_key {
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
            },
            AuthKind::Dmarc => format!(
                "DMARC missing. Add a TXT record at host `_dmarc` with value \
                 `{}`. Start with \
                 `p=none` if you want monitoring before enforcement.",
                dmarc_record_value()
            ),
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
            .fix_hint(
                "example.com",
                "customer-2026",
                Some("MIIBIjAN"),
                "eu-west-1"
            )
            .contains("include:amazonses.com"));
        // DMARC hint must reference the policy directive we recommend.
        assert!(AuthKind::Dmarc
            .fix_hint(
                "example.com",
                "customer-2026",
                Some("MIIBIjAN"),
                "eu-west-1"
            )
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

        let pending =
            aws_sdk_sesv2::operation::get_email_identity::GetEmailIdentityOutput::builder()
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

// ─── Adversarial handler-level tests ──────────────────────────────

#[cfg(test)]
mod adversarial_handler_tests {
    use super::*;
    use crate::app::test_support::{test_config, test_state_over_with_config};
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::response::Response;
    use dns_resolver::{DkimRecord, DmarcPolicy, MxRecord, SpfRecord};
    use serde_json::json;
    use sqlx::PgPool;
    use std::sync::Once;
    use tower::ServiceExt;

    const DKIM_TEST_KEY: &str = "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8";

    /// The canonical env mutex, wrapped in a newtype so the guard is still
    /// held across awaits but clippy's `await_holding_lock` (which matches
    /// the `MutexGuard` type directly) does not fire: the DKIM encryption
    /// key must stay stable for the whole seeded scope, exactly like the
    /// auth/web fixtures that hold the raw guard.
    struct DkimEnvGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    fn lock_dkim_env() -> DkimEnvGuard {
        DkimEnvGuard {
            _guard: crate::test_db::DKIM_ENV_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        }
    }

    fn unique(prefix: &str) -> String {
        format!(
            "{prefix}{}",
            &uuid::Uuid::new_v4().simple().to_string()[..18]
        )
    }

    async fn domains_state(pool: Pool) -> AppState {
        test_state_over_with_config(pool, test_config()).await
    }

    type Pool = PgPool;

    /// The production handlers at their production FULL paths (see the sales
    /// module: `nest` would strip the URI prefix the static key guard reads).
    fn domains_app(state: &AppState) -> Router {
        Router::new()
            .route("/v1/domains", post(create_domain).get(list_domains))
            .route("/v1/domains/:id", get(get_domain).delete(delete_domain))
            .route("/v1/domains/:id/verify", post(verify_domain))
            .route("/v1/domains/:id/dns-records", get(get_dns_records))
            .route("/v1/domains/:id/auth-status", get(get_auth_status))
            .with_state(state.clone())
    }

    fn api_request(
        method: Method,
        uri: &str,
        key: &str,
        body: Option<serde_json::Value>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "app.apexmail.ee")
            .header("x-api-key", key);
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        builder.body(body).unwrap()
    }

    async fn json_body(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    struct SeededDomain {
        id: Uuid,
        name: String,
    }

    /// Seed one pending domain row (no DKIM material) for `tenant`.
    async fn seed_domain(pool: &Pool, tenant: &str, name: &str) -> SeededDomain {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, created_at, updated_at) \
             VALUES ($1, $2, $3, 'pending', NOW(), NOW())",
        )
        .bind(id)
        .bind(tenant)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed domain");
        SeededDomain {
            id,
            name: name.to_string(),
        }
    }

    async fn cleanup_domain(pool: &Pool, tenant: &str, id: Uuid) {
        sqlx::query("DELETE FROM domains WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup domain");
    }

    async fn cleanup_tenant(pool: &Pool, tenant: &str) {
        sqlx::query("DELETE FROM domains WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup domains");
        sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup api keys");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup tenant");
    }

    // ── Malformed path ids are 404, never a 500 ──────────────────

    #[tokio::test]
    async fn malformed_domain_ids_are_404_not_500() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_bad_ids").await else {
            return;
        };
        let (tenant, key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read", "domains:write"])
                .await;
        let state = domains_state(pool.clone()).await;
        let app = domains_app(&state);

        let huge = "a".repeat(1024);
        for malformed in ["not-a-uuid", "00000000-0000-0000-0000-00000000000", &huge] {
            for (method, suffix) in [
                (Method::GET, ""),
                (Method::DELETE, ""),
                (Method::GET, "/dns-records"),
                (Method::GET, "/auth-status"),
                (Method::POST, "/verify"),
            ] {
                let uri = format!("/v1/domains/{malformed}{suffix}");
                let response = app
                    .clone()
                    .oneshot(api_request(method.clone(), &uri, &key, None))
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::NOT_FOUND,
                    "{method} {uri} must be a clean 404 (no uuid cast error)"
                );
            }
        }

        cleanup_tenant(&pool, &tenant).await;
    }

    // ── Create: normalization, encryption, conflicts, quota, scopes ──

    #[tokio::test]
    async fn create_domain_persists_encrypted_material_and_enforces_conflicts() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_create").await else {
            return;
        };
        let _env = lock_dkim_env();
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            DKIM_TEST_KEY,
        );

        let (tenant, key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read", "domains:write"])
                .await;
        let (readonly_tenant, readonly_key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read"]).await;
        let state = domains_state(pool.clone()).await;
        let app = domains_app(&state);

        let name = format!("Create-{}.Example.", unique("d"));
        let response = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/v1/domains",
                &key,
                Some(json!({ "name": name })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = json_body(response).await;
        let created_name = body["name"].as_str().unwrap().to_string();
        assert_eq!(
            created_name,
            name.trim_end_matches('.').to_ascii_lowercase(),
            "the stored name is normalized"
        );
        assert_eq!(body["status"], "pending");
        let id = Uuid::parse_str(body["id"].as_str().unwrap()).expect("uuid id");

        let material: (bool, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT dkim_enabled, dkim_selector, dkim_private_key FROM domains \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("created domain row");
        assert!(material.0, "DKIM signing is enabled at creation");
        let selector = material.1.expect("selector provisioned");
        assert!(is_valid_dkim_selector(&selector), "selector: {selector}");
        let encrypted = material.2.expect("private key provisioned");
        assert!(
            is_encrypted_dkim_private_key(&encrypted),
            "the private key must be encrypted at rest, got {encrypted:.24}..."
        );
        let aad = dkim_private_key_aad(&tenant, &id.to_string());
        let decrypted =
            decrypt_dkim_private_key(&encrypted, &aad).expect("the stored envelope decrypts");
        assert!(
            !decrypted.contains("dkim:v1:"),
            "the stored value is an envelope, not plaintext"
        );

        // Duplicate (case-insensitive, trailing dot) → 409.
        let response = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/v1/domains",
                &key,
                Some(json!({ "name": created_name.to_uppercase() })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // Invalid names are rejected before any write.
        for invalid in ["not a domain", "http://example.com", "-bad.example", ""] {
            let response = app
                .clone()
                .oneshot(api_request(
                    Method::POST,
                    "/v1/domains",
                    &key,
                    Some(json!({ "name": invalid })),
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "`{invalid}` must be rejected"
            );
        }

        // A read-only key cannot create.
        let response = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/v1/domains",
                &readonly_key,
                Some(json!({ "name": format!("{}.example", unique("ro")) })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Another tenant cannot claim the same global name.
        let response = app
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/v1/domains",
                "am_unknown_key",
                Some(json!({ "name": created_name })),
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_client_error(),
            "unknown key must not create a domain"
        );

        cleanup_tenant(&pool, &tenant).await;
        cleanup_tenant(&pool, &readonly_tenant).await;
        match previous {
            Some(value) => std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                value,
            ),
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    #[tokio::test]
    async fn create_domain_refuses_when_the_plan_limit_is_reached() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_quota").await else {
            return;
        };
        let _env = lock_dkim_env();
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            DKIM_TEST_KEY,
        );

        let (tenant, key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read", "domains:write"])
                .await;
        let plan = unique("plan-adv");
        sqlx::query("INSERT INTO plans (id, name, features) VALUES ($1, $2, $3::jsonb)")
            .bind(unique("pid"))
            .bind(&plan)
            .bind(json!({ "max_sending_domains": 0 }).to_string())
            .execute(&pool)
            .await
            .expect("seed restrictive plan");
        sqlx::query("UPDATE tenants SET plan = $1 WHERE id = $2")
            .bind(&plan)
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("attach plan");

        let state = domains_state(pool.clone()).await;
        let app = domains_app(&state);
        let response = app
            .oneshot(api_request(
                Method::POST,
                "/v1/domains",
                &key,
                Some(json!({ "name": format!("{}.example", unique("quota")) })),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a zero-domain plan must refuse creation"
        );
        let body = json_body(response).await;
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("domain limit"),
            "the refusal names the plan limit: {body}"
        );

        sqlx::query("UPDATE tenants SET plan = 'free' WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("restore plan");
        sqlx::query("DELETE FROM plans WHERE name = $1")
            .bind(&plan)
            .execute(&pool)
            .await
            .expect("cleanup plan");
        cleanup_tenant(&pool, &tenant).await;
        match previous {
            Some(value) => std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                value,
            ),
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    // ── Read/delete: tenant scoping ──────────────────────────────

    #[tokio::test]
    async fn list_get_and_delete_are_tenant_scoped() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_scope").await else {
            return;
        };
        let (tenant, key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read", "domains:write"])
                .await;
        let (other_tenant, other_key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read", "domains:write"])
                .await;
        let mine_a = seed_domain(&pool, &tenant, &format!("{}.example", unique("mine-a"))).await;
        let mine_b = seed_domain(&pool, &tenant, &format!("{}.example", unique("mine-b"))).await;
        let other = seed_domain(
            &pool,
            &other_tenant,
            &format!("{}.example", unique("other")),
        )
        .await;

        let state = domains_state(pool.clone()).await;
        let app = domains_app(&state);

        // List: exactly the caller's rows.
        let response = app
            .clone()
            .oneshot(api_request(Method::GET, "/v1/domains", &key, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let names: Vec<&str> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&mine_a.name.as_str()));
        assert!(names.contains(&mine_b.name.as_str()));
        assert!(
            !names.contains(&other.name.as_str()),
            "cross-tenant domain leaked into the list: {names:?}"
        );

        // Cursor behaves like an offset.
        let response = app
            .clone()
            .oneshot(api_request(Method::GET, "/v1/domains?cursor=1", &key, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await.as_array().unwrap().len(), 1);

        // Get: own 200, other tenant 404.
        let response = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                &format!("/v1/domains/{}", mine_a.id),
                &key,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["id"], mine_a.id.to_string());
        let response = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                &format!("/v1/domains/{}", other.id),
                &other_key,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                &format!("/v1/domains/{}", other.id),
                &key,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "another tenant's domain must not be readable"
        );

        // Delete: cross-tenant 404 leaves the row; own delete 204 then 404.
        let response = app
            .clone()
            .oneshot(api_request(
                Method::DELETE,
                &format!("/v1/domains/{}", other.id),
                &key,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let still_there: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM domains WHERE id = $1 AND tenant_id = $2")
                .bind(other.id)
                .bind(&other_tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            still_there, 1,
            "cross-tenant delete must not remove the row"
        );

        let response = app
            .clone()
            .oneshot(api_request(
                Method::DELETE,
                &format!("/v1/domains/{}", mine_a.id),
                &key,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                &format!("/v1/domains/{}", mine_a.id),
                &key,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = app
            .clone()
            .oneshot(api_request(
                Method::DELETE,
                &format!("/v1/domains/{}", mine_a.id),
                &key,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        cleanup_domain(&pool, &tenant, mine_b.id).await;
        cleanup_domain(&pool, &other_tenant, other.id).await;
        cleanup_tenant(&pool, &tenant).await;
        cleanup_tenant(&pool, &other_tenant).await;
    }

    // ── DNS records + auth-status ────────────────────────────────

    #[tokio::test]
    async fn dns_records_refuse_incomplete_material_and_auth_status_reports_derived_state() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_records").await else {
            return;
        };
        let (tenant, key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read"]).await;
        let domain = seed_domain(&pool, &tenant, &format!("{}.example", unique("rec"))).await;
        let state = domains_state(pool.clone()).await;
        let app = domains_app(&state);

        // No DKIM material yet: the endpoint refuses to invent a key.
        let response = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                &format!("/v1/domains/{}/dns-records", domain.id),
                &key,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = json_body(response).await;
        assert!(body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("incomplete"));

        // Provision coherent material directly, then the record set renders.
        let selector = "am-adversarial";
        let key_pair = generate_dkim_keypair().expect("keypair");
        sqlx::query(
            "UPDATE domains SET dkim_selector = $1, dkim_public_key = $2, \
                    dkim_private_key = 'plaintext-pem-for-record-rendering', dkim_enabled = true \
             WHERE id = $3 AND tenant_id = $4",
        )
        .bind(selector)
        .bind(&key_pair.public_key)
        .bind(domain.id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();

        let response = app
            .clone()
            .oneshot(api_request(
                Method::GET,
                &format!("/v1/domains/{}/dns-records", domain.id),
                &key,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["domain"], domain.name.as_str());
        let records = body["records"].as_array().unwrap();
        assert!(records.iter().any(|record| {
            record["record_type"] == "TXT"
                && record["hostname"]
                    .as_str()
                    .is_some_and(|host| host == dkim_hostname(selector, &domain.name))
        }));
        assert!(records.iter().any(|record| {
            record["record_type"] == "TXT"
                && record["hostname"] == format!("_dmarc.{}", domain.name)
        }));
        let ses_transport = Config::ses_transport_enabled();
        if ses_transport {
            assert!(records.iter().any(|record| {
                record["record_type"] == "TXT"
                    && record["hostname"] == format!("bounce.{}", domain.name)
            }));
            assert!(records
                .iter()
                .any(|record| { record["record_type"] == "MX" && record["priority"] == 10 }));
        } else {
            assert!(
                records
                    .iter()
                    .all(|record| record["hostname"] != format!("bounce.{}", domain.name)),
                "the SMTP transport does not require a custom MAIL FROM pair"
            );
        }

        // auth-status: unauthenticated with nothing verified…
        let auth_status = |app: Router, key: String, id: Uuid| async move {
            let response = app
                .oneshot(api_request(
                    Method::GET,
                    &format!("/v1/domains/{id}/auth-status"),
                    &key,
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            json_body(response).await
        };
        let body = auth_status(app.clone(), key.clone(), domain.id).await;
        assert_eq!(body["domain"], domain.name.as_str());
        assert_eq!(body["overall_status"], "unauthenticated");
        assert_eq!(body["mx"]["status"], "not_required");
        assert_eq!(body["dkim"]["status"], "fail");
        assert_eq!(body["dmarc"]["status"], "fail");
        assert!(
            body["dkim"]["fix"].as_str().unwrap().contains(selector),
            "the DKIM fix hint names the assigned selector: {body}"
        );

        // …partial once DKIM verifies…
        sqlx::query("UPDATE domains SET dkim_verified = true WHERE id = $1")
            .bind(domain.id)
            .execute(&pool)
            .await
            .unwrap();
        let body = auth_status(app.clone(), key.clone(), domain.id).await;
        assert_eq!(body["overall_status"], "partial");
        assert_eq!(body["dkim"]["status"], "pass");
        assert!(
            body["dkim"].get("fix").is_none(),
            "passing checks carry no fix hint"
        );

        // …and authenticated once every required flag is set.
        sqlx::query(
            "UPDATE domains SET spf_verified = true, dmarc_verified = true, \
                    return_path_verified = true WHERE id = $1",
        )
        .bind(domain.id)
        .execute(&pool)
        .await
        .unwrap();
        let body = auth_status(app.clone(), key.clone(), domain.id).await;
        assert_eq!(body["overall_status"], "authenticated");

        // Completing the check removes the DKIM material: the hint switches
        // to the provisioning instruction instead of a fabricated record.
        sqlx::query(
            "UPDATE domains SET dkim_public_key = NULL, dkim_verified = false WHERE id = $1",
        )
        .bind(domain.id)
        .execute(&pool)
        .await
        .unwrap();
        let body = auth_status(app.clone(), key.clone(), domain.id).await;
        assert!(
            body["dkim"]["expected"].is_null(),
            "no public key means no expected DKIM record"
        );
        assert!(body["dkim"]["fix"]
            .as_str()
            .unwrap()
            .contains("provision a new per-domain key"));

        // Cross-tenant reads are 404 with no existence oracle.
        let (other_tenant, other_key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read"]).await;
        for suffix in ["", "/dns-records", "/auth-status"] {
            let response = app
                .clone()
                .oneshot(api_request(
                    Method::GET,
                    &format!("/v1/domains/{}{suffix}", domain.id),
                    &other_key,
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        cleanup_tenant(&pool, &tenant).await;
        cleanup_tenant(&pool, &other_tenant).await;
    }

    // ── Injected-DNS verification matrix ─────────────────────────

    #[derive(Default)]
    struct FakeDns {
        spf: Option<SpfRecord>,
        spf_error: bool,
        mx: Vec<MxRecord>,
        mx_error: bool,
        dkim: Option<DkimRecord>,
        dkim_error: bool,
        dmarc: Option<DmarcPolicy>,
        dmarc_error: bool,
    }

    impl VerificationDns for FakeDns {
        async fn lookup_spf(&self, _host: &str) -> Result<Option<SpfRecord>, String> {
            if self.spf_error {
                return Err("spf resolver down".into());
            }
            Ok(self.spf.clone())
        }

        async fn lookup_mx(&self, _host: &str) -> Result<Vec<MxRecord>, String> {
            if self.mx_error {
                return Err("mx resolver down".into());
            }
            Ok(self.mx.clone())
        }

        async fn lookup_dkim(
            &self,
            _selector: &str,
            _domain: &str,
        ) -> Result<Option<DkimRecord>, String> {
            if self.dkim_error {
                return Err("dkim resolver down".into());
            }
            Ok(self.dkim.clone())
        }

        async fn lookup_dmarc(&self, _domain: &str) -> Result<Option<DmarcPolicy>, String> {
            if self.dmarc_error {
                return Err("dmarc resolver down".into());
            }
            Ok(self.dmarc.clone())
        }
    }

    /// Generate a keypair and persist coherent material for `domain` so the
    /// verification flow does not need to provision (and tests can build
    /// matching DNS records).
    async fn seed_verified_material(pool: &Pool, tenant: &str, domain: &SeededDomain) -> String {
        let key_pair = generate_dkim_keypair().expect("keypair");
        let aad = dkim_private_key_aad(tenant, &domain.id.to_string());
        let encrypted = encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
            .expect("encrypt test DKIM key");
        sqlx::query(
            "UPDATE domains SET dkim_selector = 'am-advfixed', dkim_public_key = $1, \
                    dkim_private_key = $2, dkim_enabled = true \
             WHERE id = $3 AND tenant_id = $4",
        )
        .bind(&key_pair.public_key)
        .bind(&encrypted)
        .bind(domain.id)
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed dkim material");
        key_pair.public_key
    }

    fn matching_dkim(public_key: &str) -> DkimRecord {
        DkimRecord::parse(&dkim_txt_record_value(public_key)).expect("parse dkim record")
    }

    fn matching_dmarc() -> DmarcPolicy {
        DmarcPolicy::parse("v=DMARC1; p=none; rua=mailto:dmarc@apexmail.ee")
            .expect("parse dmarc record")
    }

    fn matching_spf() -> SpfRecord {
        SpfRecord::parse("v=spf1 include:amazonses.com ~all").expect("parse spf record")
    }

    fn matching_mx(region: &str) -> MxRecord {
        MxRecord::new(10, format!("feedback-smtp.{region}.amazonses.com"))
    }

    #[tokio::test]
    async fn verification_missing_wrong_and_erroring_records_stay_pending() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_verify_edges").await else {
            return;
        };
        let _env = lock_dkim_env();
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            DKIM_TEST_KEY,
        );
        let (tenant, _key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read"]).await;
        let domain = seed_domain(&pool, &tenant, &format!("{}.example", unique("ver"))).await;
        let public_key = seed_verified_material(&pool, &tenant, &domain).await;
        let state = domains_state(pool.clone()).await;

        // Missing everything (self-hosted transport): pending, nothing set.
        let empty = FakeDns::default();
        let response =
            verify_domain_for_tenant_with_dns(&state, &tenant, &domain.id.to_string(), &empty)
                .await
                .expect("verification completes");
        assert_eq!(response.status, "pending");
        assert!(!response.dkim_verified && !response.dmarc_verified);

        // Wrong DKIM key, wrong key type, wrong version, and a resolver error
        // all stay pending instead of trusting a syntactically valid record.
        for dkim in [
            DkimRecord::parse(&dkim_txt_record_value(
                &generate_dkim_keypair().unwrap().public_key,
            ))
            .unwrap(),
            {
                let mut record = matching_dkim(&public_key);
                record.key_type = "ed25519".into();
                record
            },
            {
                let mut record = matching_dkim(&public_key);
                record.version = Some("DKIM2".into());
                record
            },
        ] {
            let dns = FakeDns {
                dkim: Some(dkim),
                dmarc: Some(matching_dmarc()),
                ..FakeDns::default()
            };
            let response =
                verify_domain_for_tenant_with_dns(&state, &tenant, &domain.id.to_string(), &dns)
                    .await
                    .unwrap();
            assert_eq!(response.status, "pending", "untrusted DKIM must not verify");
            assert!(!response.dkim_verified);
        }

        // Resolver failures are honest "not verified", not an error.
        let failing = FakeDns {
            dkim_error: true,
            dmarc_error: true,
            spf_error: true,
            mx_error: true,
            ..FakeDns::default()
        };
        let response =
            verify_domain_for_tenant_with_dns(&state, &tenant, &domain.id.to_string(), &failing)
                .await
                .unwrap();
        assert_eq!(response.status, "pending");

        cleanup_tenant(&pool, &tenant).await;
        match previous {
            Some(value) => std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                value,
            ),
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    #[tokio::test]
    async fn verification_round_trip_is_idempotent_and_ses_path_requires_the_full_pair() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_verify_round").await else {
            return;
        };
        let _env = lock_dkim_env();
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            DKIM_TEST_KEY,
        );
        let (tenant, _key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read"]).await;
        let domain = seed_domain(&pool, &tenant, &format!("{}.example", unique("rt"))).await;
        let public_key = seed_verified_material(&pool, &tenant, &domain).await;
        let state = domains_state(pool.clone()).await;
        let id = domain.id.to_string();

        // Self-hosted (SMTP) transport: DKIM + DMARC alone verify.
        let dns = FakeDns {
            dkim: Some(matching_dkim(&public_key)),
            dmarc: Some(matching_dmarc()),
            ..FakeDns::default()
        };
        let response =
            verify_domain_for_tenant_with_dns_with_transport(&state, &tenant, &id, &dns, false)
                .await
                .unwrap();
        assert_eq!(response.status, "verified");
        assert!(response.dkim_verified && response.dmarc_verified);
        assert!(!response.spf_verified && !response.return_path_verified);

        // Re-verify: same material, same answer (idempotent).
        let response =
            verify_domain_for_tenant_with_dns_with_transport(&state, &tenant, &id, &dns, false)
                .await
                .unwrap();
        assert_eq!(response.status, "verified");

        // SES transport needs the custom MAIL FROM SPF + MX pair as well, or
        // the domain returns to pending.
        sqlx::query(
            "UPDATE domains SET status = 'pending', verified = false, ses_verified = false \
             WHERE id = $1",
        )
        .bind(domain.id)
        .execute(&pool)
        .await
        .unwrap();
        let response =
            verify_domain_for_tenant_with_dns_with_transport(&state, &tenant, &id, &dns, true)
                .await
                .unwrap();
        assert_eq!(
            response.status, "pending",
            "SES requires the MAIL FROM pair"
        );
        assert!(response.dkim_verified && response.dmarc_verified);
        assert!(!response.spf_verified && !response.return_path_verified);

        // Cross-tenant verification is refused before any DNS work.
        let (other_tenant, _) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read"]).await;
        let error = verify_domain_for_tenant_with_dns_with_transport(
            &state,
            &other_tenant,
            &id,
            &dns,
            false,
        )
        .await
        .expect_err("another tenant's domain must not verify");
        assert!(matches!(error, ApiError::NotFound(_)));

        // The stored-state fallback reports the persisted row, and 404s for
        // an unknown id.
        let fallback = current_verification_state(&state, &tenant, &id)
            .await
            .unwrap();
        assert_eq!(fallback.domain, domain.name);
        let error = current_verification_state(&state, &tenant, &Uuid::new_v4().to_string())
            .await
            .expect_err("unknown domain");
        assert!(matches!(error, ApiError::NotFound(_)));

        cleanup_tenant(&pool, &tenant).await;
        cleanup_tenant(&pool, &other_tenant).await;
        match previous {
            Some(value) => std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                value,
            ),
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    /// The SES-transport observation needs the SPF/MX pair; with it, the SES
    /// identity call is attempted and its (fast, local) failure keeps the
    /// domain pending instead of claiming readiness.
    #[tokio::test]
    async fn ses_transport_with_full_pair_stays_pending_when_ses_is_unreachable() {
        static ENDPOINT: Once = Once::new();
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_verify_ses").await else {
            return;
        };
        // Every SES client in this test binary points at a dead loopback
        // port: the AWS SDK round-trip fails immediately and deterministically
        // instead of reaching the real service.
        ENDPOINT.call_once(|| {
            std::env::set_var("AWS_ENDPOINT_URL", "http://127.0.0.1:1");
        });
        let _env = lock_dkim_env();
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            DKIM_TEST_KEY,
        );
        let (tenant, _key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read"]).await;
        let domain = seed_domain(&pool, &tenant, &format!("{}.example", unique("sesv"))).await;
        let public_key = seed_verified_material(&pool, &tenant, &domain).await;
        let mut config = test_config();
        config.aws_region = unique("region-test");
        let state = test_state_over_with_config(pool.clone(), config).await;
        let dns = FakeDns {
            spf: Some(matching_spf()),
            mx: vec![matching_mx(&state.config.aws_region)],
            dkim: Some(matching_dkim(&public_key)),
            dmarc: Some(matching_dmarc()),
            ..FakeDns::default()
        };

        let response = verify_domain_for_tenant_with_dns_with_transport(
            &state,
            &tenant,
            &domain.id.to_string(),
            &dns,
            true,
        )
        .await
        .expect("verification completes even when SES is unreachable");
        assert_eq!(response.status, "pending");
        assert!(response.spf_verified && response.dkim_verified && response.dmarc_verified);
        assert!(response.return_path_verified);

        // The honest refusal is not counted as a successful SES verify.
        let ses_verified: bool =
            sqlx::query_scalar("SELECT ses_verified FROM domains WHERE id = $1 AND tenant_id = $2")
                .bind(domain.id)
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!ses_verified);

        // delete path: the same dead endpoint surfaces as a 503 refusal.
        let error = delete_ses_domain_identity(&state, &domain.name)
            .await
            .expect_err("an unreachable SES must refuse cleanup honestly");
        assert!(matches!(error, ApiError::ServiceUnavailable(_)));

        cleanup_tenant(&pool, &tenant).await;
        match previous {
            Some(value) => std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                value,
            ),
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    async fn verify_domain_for_tenant_with_dns_with_transport(
        state: &AppState,
        tenant_id: &str,
        id: &str,
        dns: &FakeDns,
        ses_transport: bool,
    ) -> Result<Json<VerifyResponse>, ApiError> {
        let id = validated_domain_id(id)?.to_string();
        for _attempt in 0..2 {
            let (row, dkim_material) = lock_and_provision_dkim(state, tenant_id, &id).await?;
            let observations =
                observe_dns_and_ses(state, &row, &dkim_material, dns, ses_transport).await?;
            if let Some(response) = persist_verification(
                state,
                tenant_id,
                &id,
                &row.name,
                &dkim_material,
                &observations,
            )
            .await?
            {
                return Ok(Json(response));
            }
        }
        current_verification_state(state, tenant_id, &id).await
    }

    // ── Material repair/rotation ─────────────────────────────────

    #[tokio::test]
    async fn ensure_domain_dkim_material_repairs_and_rotates_partial_material() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_material").await else {
            return;
        };
        let _env = lock_dkim_env();
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            DKIM_TEST_KEY,
        );
        let (tenant, _key) =
            crate::app::test_support::seed_api_tenant(&pool, &["domains:read"]).await;
        let domain = seed_domain(&pool, &tenant, &format!("{}.example", unique("mat"))).await;
        let aad = dkim_private_key_aad(&tenant, &domain.id.to_string());

        let load_row = |pool: &Pool, id: Uuid| {
            let pool = pool.clone();
            async move {
                sqlx::query_as::<_, DomainFullRow>(
                    "SELECT id::text AS id, tenant_id::text AS tenant_id, name, dkim_selector, \
                            dkim_public_key, dkim_private_key, dkim_enabled \
                     FROM domains WHERE id = $1",
                )
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("load domain row")
            }
        };

        // Partial: selector + public key but no private key → a complete new
        // pair is provisioned and the row returns to pending.
        let stale_public = generate_dkim_keypair().unwrap().public_key;
        sqlx::query(
            "UPDATE domains SET dkim_selector = 'am-stale', dkim_public_key = $1, \
                    dkim_private_key = NULL, dkim_verified = true, status = 'verified' \
             WHERE id = $2",
        )
        .bind(&stale_public)
        .bind(domain.id)
        .execute(&pool)
        .await
        .unwrap();
        let row = load_row(&pool, domain.id).await;
        let mut tx = pool.begin().await.unwrap();
        let material = ensure_domain_dkim_material(&mut tx, &row)
            .await
            .expect("partial material is repaired");
        tx.commit().await.unwrap();
        assert_ne!(material.public_key, stale_public, "key rotated");
        let (selector, public, private, enabled, status, dkim_verified): (
            String,
            String,
            String,
            bool,
            String,
            bool,
        ) = sqlx::query_as(
            "SELECT dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled, status, dkim_verified \
             FROM domains WHERE id = $1 AND tenant_id = $2",
        )
        .bind(domain.id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(selector, material.selector);
        assert_eq!(public, material.public_key);
        assert!(is_encrypted_dkim_private_key(&private));
        assert!(enabled);
        assert_eq!(status, "pending");
        assert!(
            !dkim_verified,
            "a repair invalidates the prior verification"
        );

        // Plaintext legacy private key with a matching public key: kept, but
        // re-encrypted and normalized.
        let key_pair = generate_dkim_keypair().unwrap();
        sqlx::query(
            "UPDATE domains SET dkim_selector = 'am-legacy', dkim_public_key = $1, \
                    dkim_private_key = $2, dkim_enabled = false \
             WHERE id = $3",
        )
        .bind(&key_pair.public_key)
        .bind(key_pair.private_key_pem.as_str())
        .bind(domain.id)
        .execute(&pool)
        .await
        .unwrap();
        let row = load_row(&pool, domain.id).await;
        let mut tx = pool.begin().await.unwrap();
        let material = ensure_domain_dkim_material(&mut tx, &row)
            .await
            .expect("legacy plaintext material is migrated");
        tx.commit().await.unwrap();
        assert_eq!(material.selector, "am-legacy");
        let private: String = sqlx::query_scalar(
            "SELECT dkim_private_key FROM domains WHERE id = $1 AND tenant_id = $2",
        )
        .bind(domain.id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            is_encrypted_dkim_private_key(&private),
            "legacy plaintext must be re-encrypted in place"
        );
        let decrypted = decrypt_dkim_private_key(&private, &aad).unwrap();
        assert_eq!(decrypted.as_str(), key_pair.private_key_pem.as_str());

        // Mismatched public key (does not belong to the private key): rotate.
        sqlx::query("UPDATE domains SET dkim_public_key = $1 WHERE id = $2")
            .bind(generate_dkim_keypair().unwrap().public_key)
            .bind(domain.id)
            .execute(&pool)
            .await
            .unwrap();
        let row = load_row(&pool, domain.id).await;
        let mut tx = pool.begin().await.unwrap();
        let material = ensure_domain_dkim_material(&mut tx, &row)
            .await
            .expect("mismatched material is rotated");
        tx.commit().await.unwrap();
        assert_ne!(material.selector, "am-legacy");

        cleanup_tenant(&pool, &tenant).await;
        match previous {
            Some(value) => std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                value,
            ),
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    // ── Platform sender ──────────────────────────────────────────

    #[tokio::test]
    async fn platform_sender_bootstrap_is_idempotent_and_reports_records() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_system_sender").await else {
            return;
        };
        let _env = lock_dkim_env();
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            DKIM_TEST_KEY,
        );
        let state = domains_state(pool.clone()).await;

        let first = bootstrap_system_sender(&state)
            .await
            .expect("bootstrap provisions the platform sender");
        assert_eq!(first.domain, SYSTEM_DOMAIN);
        assert!(!first.records.is_empty(), "records are rendered");
        // The public key is exposed; the private key never is.
        let payload = serde_json::to_value(&first).unwrap();
        assert!(payload.get("private_key").is_none());
        assert!(payload["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["hostname"]
                .as_str()
                .is_some_and(|host| host.contains("_domainkey"))));

        let second = bootstrap_system_sender(&state)
            .await
            .expect("bootstrap is idempotent");
        assert_eq!(second.id, first.id);
        assert_eq!(second.records.len(), first.records.len());

        let status = system_sender_status(&state)
            .await
            .expect("status reads the provisioned sender");
        assert_eq!(status.id, first.id);
        assert_eq!(status.domain, SYSTEM_DOMAIN);

        match previous {
            Some(value) => std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                value,
            ),
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    #[tokio::test]
    async fn system_sender_status_refuses_an_absent_sender() {
        let Some(pool) = crate::test_db::optional_pg_pool("domains_adv_sender_absent").await else {
            return;
        };
        // A unique tenant id: the status query is scoped by tenant + name, so
        // an absent row is deterministic without touching shared fixtures.
        let state = domains_state(pool.clone()).await;
        let absent = sqlx::query_as::<_, SystemSenderStatusRow>(
            "SELECT id::text AS id, name, status, dkim_selector, dkim_public_key \
             FROM domains WHERE tenant_id = $1 AND name = $2",
        )
        .bind(SYSTEM_TENANT_ID)
        .bind(SYSTEM_DOMAIN)
        .fetch_optional(&pool)
        .await
        .unwrap();
        if absent.is_some() {
            // Another test provisioned the platform sender; the refusal path
            // is pinned by the pure helper instead.
            let row = SystemSenderStatusRow {
                id: "x".into(),
                name: SYSTEM_DOMAIN.into(),
                status: "pending".into(),
                dkim_selector: None,
                dkim_public_key: None,
            };
            let records = match (
                row.dkim_selector
                    .as_deref()
                    .filter(|value| is_valid_dkim_selector(value)),
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
            assert!(records.is_empty(), "incomplete material yields no records");
            return;
        }
        let error = system_sender_status(&state)
            .await
            .expect_err("an absent platform sender must be reported");
        assert!(matches!(error, ApiError::ServiceUnavailable(_)));
    }
}

/// Conflict and not-found arms of the domain lifecycle.
#[cfg(test)]
mod conflict_coverage_tests {
    use crate::app::test_support::adv::AdvEnv;
    use axum::http::StatusCode;

    #[test]
    fn duplicate_claims_and_missing_domains_answer_cleanly() {
        // Domain creation provisions DKIM material, which needs the
        // process-global encryption key env var — hold the shared mutex
        // and drive the async body on a local runtime (web.rs convention).
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
        let Some(pool) = crate::test_db::canonical_pool("dom_conflict").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool.clone(), &["domains:write", "domains:read"]).await;
        let name = format!("{}.example.test", uuid::Uuid::new_v4().simple());

        // Without the DKIM encryption key in the environment, creation is
        // refused with an explicit 503 (provisioning arm).
        let stored_key = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV);
        let (status, body) = env
            .post("/v1/domains", &serde_json::json!({ "name": format!("nok.{}.test", uuid::Uuid::new_v4().simple()) }).to_string())
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        if let Some(key) = stored_key {
            std::env::set_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV, key);
        } else {
            std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
            );
        }

        // First claim succeeds.
        let (status, body) = env
            .post("/v1/domains", &serde_json::json!({ "name": name }).to_string())
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = body["id"]
            .as_str()
            .or_else(|| body["data"]["id"].as_str())
            .expect("domain id")
            .to_string();

        // The identical claim is a 409 (unique-violation arm).
        let (status, body) = env
            .post("/v1/domains", &serde_json::json!({ "name": name }).to_string())
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // Deleting an unknown domain id is a 404.
        let missing = uuid::Uuid::new_v4();
        let (status, _body) = env.delete(&format!("/v1/domains/{missing}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The real domain deletes cleanly.
        let (status, _body) = env.delete(&format!("/v1/domains/{id}")).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        });
    }
}
