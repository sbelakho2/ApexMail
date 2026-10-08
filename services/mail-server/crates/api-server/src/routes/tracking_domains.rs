//! Custom tracking domain lifecycle (Pro and above per `docs/pricing.md`).
//!
//! `custom_tracking_domain` is RuntimeEnforced and this module is the setup
//! half of the capability (the serving half lives in
//! `tracking-service/src/routes/custom_host.rs`):
//!
//! * `POST /v1/tracking-domains` — create (requires `domains:write` scope and
//!   the `custom_tracking_domain` entitlement). The tracking host must be a
//!   strict subdomain of a VERIFIED domain already in the tenant's account
//!   (docs/domains/tracking-domain.md), one per verified domain, with the
//!   first label not a reserved mail/web role.
//! * `GET /v1/tracking-domains` / `GET /v1/tracking-domains/:id` — read.
//! * `GET /v1/tracking-domains/:id/dns-records` — the exact CNAME the
//!   customer must publish (`host` → the platform tracking host).
//! * `POST /v1/tracking-domains/:id/verify` — a real DNS check: the custom
//!   host's addresses must include an address of the CNAME target. Outcomes
//!   are PENDING/VERIFIED/FAILED with the named reason, never a silent state.
//! * `DELETE /v1/tracking-domains/:id` — remove (and the tracking service
//!   stops serving the host: resolution is an explicit verified-row lookup,
//!   never a cached guess).
//!
//! Every mutation is audit-logged. Reads and deletes are deliberately NOT
//! entitlement-gated: a downgraded tenant must be able to see their state
//! and clean up; create/verify are the gated capability surface.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use billing_entitlements::FeatureKey;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

/// The label the customer CNAMEs to when the deployment does not override
/// the public tracking URL. Matches the tracking-service default
/// (`TRACKING_BASE_URL`, compose default `https://track.apexmail.ee`).
const DEFAULT_TRACKING_HOST: &str = "track.apexmail.ee";

/// First labels that collide with the mail/web roles every domain already
/// uses — docs/domains/tracking-domain.md: "The CNAME host must not conflict
/// with existing records (don't use `www`, `mail`, etc.)".
const RESERVED_TRACKING_LABELS: &[&str] = &[
    "www", "mail", "smtp", "mta", "mx", "bounce", "api", "app", "cpanel", "webmail",
];

/// Max tenant-retention-style DNS name length (RFC 1035).
const MAX_DOMAIN_LEN: usize = 253;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_tracking_domain).get(list_tracking_domains))
        .route(
            "/:id",
            get(get_tracking_domain).delete(delete_tracking_domain),
        )
        .route("/:id/dns-records", get(get_dns_records))
        .route("/:id/verify", post(verify_tracking_domain))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTrackingDomainRequest {
    pub domain: String,
}

#[derive(Debug, Serialize)]
pub struct TrackingDomainResponse {
    pub id: String,
    pub domain: String,
    pub parent_domain: String,
    /// pending | verified | failed
    pub status: String,
    /// Named reason for a pending/failed outcome; null when verified.
    pub status_reason: Option<String>,
    /// The CNAME value the customer must publish.
    pub cname_target: String,
    pub created_at: String,
    pub verified_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrackingDomainRecord {
    pub record_type: String,
    pub hostname: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct TrackingDomainRecordsResponse {
    pub domain: String,
    pub records: Vec<TrackingDomainRecord>,
}

#[derive(sqlx::FromRow)]
struct TrackingDomainRow {
    id: String,
    domain: String,
    parent_domain: String,
    status: String,
    status_reason: Option<String>,
    cname_target: String,
    created_at: DateTime<Utc>,
    verified_at: Option<DateTime<Utc>>,
}

impl From<TrackingDomainRow> for TrackingDomainResponse {
    fn from(row: TrackingDomainRow) -> Self {
        Self {
            id: row.id,
            domain: row.domain,
            parent_domain: row.parent_domain,
            status: row.status,
            status_reason: row.status_reason,
            cname_target: row.cname_target,
            created_at: row.created_at.to_rfc3339(),
            verified_at: row.verified_at.map(|at| at.to_rfc3339()),
        }
    }
}

const TRACKING_DOMAIN_COLUMNS: &str =
    "id::text AS id, domain, parent_domain, status, status_reason, \
     cname_target, created_at, verified_at";

// ─── Pure helpers ──────────────────────────────────────────────

/// Normalise a user-supplied host: trim, drop a trailing root dot, lowercase.
pub(crate) fn normalise_tracking_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The public tracking host a customer CNAMEs to, from `TRACKING_BASE_URL`
/// (the same variable the tracking service and worker read). Falls back to
/// the documented platform host on absence or an unparseable value.
pub(crate) fn default_cname_target() -> String {
    std::env::var("TRACKING_BASE_URL")
        .ok()
        .and_then(|value| cname_target_from_base_url(&value))
        .unwrap_or_else(|| DEFAULT_TRACKING_HOST.to_string())
}

/// Extract the host from a base URL (`https://track.apexmail.ee` →
/// `track.apexmail.ee`). `None` for a missing host — the caller falls back.
pub(crate) fn cname_target_from_base_url(base_url: &str) -> Option<String> {
    let parsed = base_url.trim().parse::<url::Url>().ok()?;
    let host = parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// The first (leftmost) DNS label of a hostname.
fn first_label(host: &str) -> &str {
    host.split('.').next().unwrap_or(host)
}

/// Validation errors that do not need the database. `Ok(())` means the
/// string is a syntactically valid, non-reserved tracking host candidate.
pub(crate) fn validate_tracking_domain_syntax(domain: &str) -> Result<(), String> {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
        return Err(format!(
            "invalid tracking domain `{domain}`: a hostname of at most {MAX_DOMAIN_LEN} characters is required"
        ));
    }
    if domain.starts_with('[') {
        return Err(format!(
            "invalid tracking domain `{domain}`: a tracking domain must be a DNS name, not an address literal"
        ));
    }
    if !apexmail_lib::validation::is_valid_domain(domain) {
        return Err(format!("invalid domain name: {domain}"));
    }
    if RESERVED_TRACKING_LABELS.contains(&first_label(domain)) {
        return Err(format!(
            "the host `{domain}` uses a reserved first label; choose a dedicated label such as `track` or `email` so mail and web records are not affected"
        ));
    }
    Ok(())
}

/// Truthful record set: one CNAME to the platform tracking host.
pub(crate) fn tracking_dns_records(domain: &str, cname_target: &str) -> Vec<TrackingDomainRecord> {
    vec![TrackingDomainRecord {
        record_type: "CNAME".into(),
        hostname: domain.to_string(),
        value: cname_target.to_string(),
    }]
}

fn unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "23505")
}

fn validated_id(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id.trim()).map_err(|_| ApiError::NotFound("tracking domain not found".into()))
}

// ─── Handlers ──────────────────────────────────────────────────

async fn list_tracking_domains(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<TrackingDomainResponse>>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;
    let rows = sqlx::query_as::<_, TrackingDomainRow>(&format!(
        "SELECT {TRACKING_DOMAIN_COLUMNS} FROM tracking_domains \
         WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200"
    ))
    .bind(&auth.tenant_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_tracking_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<TrackingDomainResponse>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;
    Ok(Json(
        fetch_owned_domain(&state, &auth.tenant_id, &id)
            .await?
            .into(),
    ))
}

async fn get_dns_records(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<TrackingDomainRecordsResponse>, ApiError> {
    require_scopes(&auth, &["domains:read"])?;
    let row = fetch_owned_domain(&state, &auth.tenant_id, &id).await?;
    Ok(Json(TrackingDomainRecordsResponse {
        domain: row.domain.clone(),
        records: tracking_dns_records(&row.domain, &row.cname_target),
    }))
}

async fn create_tracking_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateTrackingDomainRequest>,
) -> Result<(StatusCode, Json<TrackingDomainResponse>), ApiError> {
    require_scopes(&auth, &["domains:write"])?;
    create_tracking_domain_gated(&state, &auth.tenant_id, &body).await
}

/// The entitlement-gated create, shared by the JSON surface and the console
/// form (ONE gate, ONE lifecycle).
pub(crate) async fn create_tracking_domain_gated(
    state: &AppState,
    tenant_id: &str,
    body: &CreateTrackingDomainRequest,
) -> Result<(StatusCode, Json<TrackingDomainResponse>), ApiError> {
    // The capability gate: Pro and above per docs/pricing.md, through the
    // canonical entitlement gate.
    crate::entitlements::require_feature(state, tenant_id, FeatureKey::CustomTrackingDomain).await?;
    let target = default_cname_target();
    create_tracking_domain_with_target(state, tenant_id, body, &target).await
}

/// [`create_tracking_domain`] with an explicit CNAME target so tests never
/// depend on ambient env.
pub(crate) async fn create_tracking_domain_with_target(
    state: &AppState,
    tenant_id: &str,
    body: &CreateTrackingDomainRequest,
    cname_target: &str,
) -> Result<(StatusCode, Json<TrackingDomainResponse>), ApiError> {
    let domain = normalise_tracking_domain(&body.domain);
    validate_tracking_domain_syntax(&domain)
        .map_err(|message| ApiError::Validation(vec![message]))?;

    // The owning verified parent (item-11 owned-domain logic): the longest
    // owned domain the host is a strict subdomain of. An apex of an owned
    // domain is NOT accepted — docs require a subdomain so mail/web records
    // on the apex are never touched.
    let parent: Option<(String,)> = sqlx::query_as(
        "SELECT lower(name) FROM domains \
         WHERE tenant_id = $1 \
           AND (verified = true OR status = 'verified') \
           AND lower(name) <> $2 \
           AND right($2, length(lower(name)) + 1) = '.' || lower(name) \
         ORDER BY length(name) DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(&domain)
    .fetch_optional(&state.db)
    .await?;
    let Some((parent_domain,)) = parent else {
        return Err(ApiError::BadRequest(format!(
            "`{domain}` is not a subdomain of a verified domain in this workspace — \
             add and verify the parent domain first, then configure a tracking subdomain"
        )));
    };

    // One tracking domain per verified domain (docs limitation).
    let existing_parent: Option<(String, String)> = sqlx::query_as(
        "SELECT domain, status FROM tracking_domains WHERE tenant_id = $1 AND parent_domain = $2",
    )
    .bind(tenant_id)
    .bind(&parent_domain)
    .fetch_optional(&state.db)
    .await?;
    if let Some((existing_domain, _status)) = existing_parent {
        return Err(ApiError::Conflict(format!(
            "`{parent_domain}` already has the tracking domain `{existing_domain}` — \
             remove it before configuring another"
        )));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO tracking_domains \
         (id, tenant_id, domain, parent_domain, status, status_reason, cname_target, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $7)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(&domain)
    .bind(&parent_domain)
    .bind(format!(
        "publish the CNAME record ({domain} → {cname_target}), then verify"
    ))
    .bind(cname_target)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|error| {
        if unique_violation(&error) {
            ApiError::Conflict(format!(
                "`{domain}` is already claimed as a tracking domain"
            ))
        } else {
            error.into()
        }
    })?;

    audit(
        state,
        tenant_id,
        "tracking_domain.created",
        &id.to_string(),
        serde_json::json!({
            "domain": domain,
            "parent_domain": parent_domain,
            "cname_target": cname_target,
        }),
    )
    .await;

    info!(tenant_id = %tenant_id, domain = %domain, "custom tracking domain created");
    Ok((
        StatusCode::CREATED,
        Json(TrackingDomainResponse {
            id: id.to_string(),
            domain,
            parent_domain,
            status: "pending".into(),
            status_reason: Some(format!(
                "publish the CNAME record to {cname_target}, then verify"
            )),
            cname_target: cname_target.to_string(),
            created_at: now.to_rfc3339(),
            verified_at: None,
        }),
    ))
}

async fn verify_tracking_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<TrackingDomainResponse>, ApiError> {
    require_scopes(&auth, &["domains:write"])?;
    verify_tracking_domain_gated(&state, &auth.tenant_id, &id).await
}

/// The entitlement-gated verify, shared by the JSON surface and the console
/// form.
pub(crate) async fn verify_tracking_domain_gated(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<Json<TrackingDomainResponse>, ApiError> {
    crate::entitlements::require_feature(state, tenant_id, FeatureKey::CustomTrackingDomain).await?;
    verify_tracking_domain_with_dns(state, tenant_id, id, &SystemResolver).await
}

async fn delete_tracking_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    // Deliberately ungated by the entitlement: cleanup must always work.
    require_scopes(&auth, &["domains:write"])?;
    delete_tracking_domain_for_tenant(&state, &auth.tenant_id, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The ungated tenant-scoped delete, shared by the JSON surface and the
/// console form.
pub(crate) async fn delete_tracking_domain_for_tenant(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<(), ApiError> {
    let id = validated_id(id)?;
    let result = sqlx::query("DELETE FROM tracking_domains WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(tenant_id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("tracking domain not found".into()));
    }
    audit(
        state,
        tenant_id,
        "tracking_domain.deleted",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    info!(tenant_id = %tenant_id, tracking_domain_id = %id, "custom tracking domain deleted");
    Ok(())
}

async fn fetch_owned_domain(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<TrackingDomainRow, ApiError> {
    let id = validated_id(id)?;
    sqlx::query_as::<_, TrackingDomainRow>(&format!(
        "SELECT {TRACKING_DOMAIN_COLUMNS} FROM tracking_domains WHERE id = $1 AND tenant_id = $2"
    ))
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("tracking domain not found".into()))
}

// ─── DNS verification ──────────────────────────────────────────

/// Address resolution for verification. The production implementation uses
/// the system resolver; tests inject a deterministic fake (the same
/// injection pattern `domains.rs` uses for sender verification).
pub(crate) trait TrackingDomainDns {
    async fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>, String>;
}

/// Production resolver: resolve the custom host and the CNAME target to
/// their A/AAAA sets through the system resolver.
pub(crate) struct SystemResolver;

impl TrackingDomainDns for SystemResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        let addrs = tokio::net::lookup_host((host, 443))
            .await
            .map_err(|error| format!("{host}: {error}"))?;
        let mut ips: Vec<std::net::IpAddr> = addrs.map(|addr| addr.ip()).collect();
        ips.sort_unstable();
        ips.dedup();
        Ok(ips)
    }
}

/// [`verify_tracking_domain`] with an injected resolver. A DNS failure is a
/// `503` and leaves the stored state untouched (never a false "failed").
/// A resolvable-but-mismatching host is stored as `failed` with the NAMED
/// reason and returned in the 200 body.
pub(crate) async fn verify_tracking_domain_with_dns<D: TrackingDomainDns>(
    state: &AppState,
    tenant_id: &str,
    id: &str,
    dns: &D,
) -> Result<Json<TrackingDomainResponse>, ApiError> {
    let row = fetch_owned_domain(state, tenant_id, id).await?;

    let custom = dns.resolve(&row.domain).await.map_err(|error| {
        warn!(domain = %row.domain, error = %error, "tracking domain DNS lookup failed");
        ApiError::ServiceUnavailable(format!(
            "DNS lookup for `{}` is temporarily unavailable; the tracking domain state is unchanged — retry shortly",
            row.domain
        ))
    })?;
    let target = dns.resolve(&row.cname_target).await.map_err(|error| {
        warn!(target = %row.cname_target, error = %error, "tracking CNAME target DNS lookup failed");
        ApiError::ServiceUnavailable(format!(
            "DNS lookup for the tracking target `{}` is temporarily unavailable; the tracking domain state is unchanged — retry shortly",
            row.cname_target
        ))
    })?;

    let now = Utc::now();
    let (status, reason): (&str, Option<String>) = if !custom.is_empty()
        && custom.iter().any(|ip| target.contains(ip))
    {
        ("verified", None)
    } else {
        (
                "failed",
                Some(format!(
                    "`{}` resolves to [{}], which does not include any address of `{}` ([{}]) — publish the CNAME record exactly as shown by /dns-records, then verify again",
                    row.domain,
                    join_ips(&custom),
                    row.cname_target,
                    join_ips(&target),
                )),
            )
    };

    sqlx::query(
        "UPDATE tracking_domains SET status = $1, status_reason = $2, last_checked_at = $3, \
         verified_at = CASE WHEN $1 = 'verified' THEN $3 ELSE NULL END, updated_at = $3 \
         WHERE id = $4 AND tenant_id = $5",
    )
    .bind(status)
    .bind(reason.as_deref())
    .bind(now)
    .bind(validated_id(&row.id)?)
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    audit(
        state,
        tenant_id,
        if status == "verified" {
            "tracking_domain.verified"
        } else {
            "tracking_domain.verification_failed"
        },
        &row.id,
        serde_json::json!({
            "domain": row.domain,
            "cname_target": row.cname_target,
            "reason": reason,
        }),
    )
    .await;

    let updated = fetch_owned_domain(state, tenant_id, &row.id).await?;
    Ok(Json(updated.into()))
}

fn join_ips(ips: &[std::net::IpAddr]) -> String {
    if ips.is_empty() {
        "no addresses".to_string()
    } else {
        ips.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

async fn audit(
    state: &AppState,
    tenant_id: &str,
    action: &str,
    resource_id: &str,
    details: serde_json::Value,
) {
    if let Err(error) = crate::audit_log::insert_audit_log_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(tenant_id),
        None,
        action,
        "tracking_domain",
        Some(resource_id),
        details,
        None,
        None,
    )
    .await
    {
        // An audit write failure must be visible but must not undo a
        // completed mutation (the row is the truth; the log is the record).
        warn!(tenant_id = %tenant_id, action, error = %error, "failed to write tracking-domain audit log");
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::adv::AdvEnv;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    /// Deterministic DNS for the verification state machine.
    struct FakeDns {
        answers: HashMap<String, Result<Vec<IpAddr>, String>>,
    }

    impl TrackingDomainDns for FakeDns {
        async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            self.answers
                .get(host)
                .cloned()
                .unwrap_or_else(|| Err(format!("no scripted answer for {host}")))
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    /// Put the tenant on the REAL builtin `plan` row — the canonical
    /// RuntimeEnforced row the entitlement gate reads (`pro` grants
    /// `custom_tracking_domain`). PlanFeatures has no per-field serde
    /// default: a partial features object is corruption and would 500 by
    /// design, so the JSON always comes from the real seed.
    async fn seed_entitled_plan(pool: &sqlx::PgPool, tenant: &str, plan: &str) {
        let features =
            serde_json::to_value(&billing_service::plans::builtin_plan_seed(Some(plan)).features)
                .expect("plan features JSON");
        sqlx::query(
            "INSERT INTO plans (name, display_name, features) VALUES ($1, $1, $2) \
             ON CONFLICT (name) DO UPDATE SET features = EXCLUDED.features",
        )
        .bind(plan)
        .bind(&features)
        .execute(pool)
        .await
        .expect("seed entitled plan");
        sqlx::query("UPDATE tenants SET plan = $1 WHERE id = $2")
            .bind(plan)
            .bind(tenant)
            .execute(pool)
            .await
            .expect("switch tenant plan");
    }

    async fn seed_verified_domain(pool: &sqlx::PgPool, tenant: &str, name: &str) {
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, created_at, updated_at) \
             VALUES (gen_random_uuid(), $1, $2, 'verified', true, NOW(), NOW())",
        )
        .bind(tenant)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed verified parent domain");
    }

    async fn seed_tracking_row(
        pool: &sqlx::PgPool,
        tenant: &str,
        domain: &str,
        parent: &str,
        status: &str,
        target: &str,
    ) -> String {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tracking_domains \
             (id, tenant_id, domain, parent_domain, status, cname_target, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
        )
        .bind(id)
        .bind(tenant)
        .bind(domain)
        .bind(parent)
        .bind(status)
        .bind(target)
        .execute(pool)
        .await
        .expect("seed tracking domain row");
        id.to_string()
    }

    /// The pure policy: apex is not a subdomain; reserved labels are named.
    #[test]
    fn tracking_domain_syntax_policy() {
        assert!(validate_tracking_domain_syntax("email.example.com").is_ok());
        assert!(validate_tracking_domain_syntax("").is_err());
        assert!(validate_tracking_domain_syntax("[192.0.2.1]").is_err());
        assert!(validate_tracking_domain_syntax("not a domain").is_err());
        let reserved =
            validate_tracking_domain_syntax("www.example.com").expect_err("www must be refused");
        assert!(reserved.contains("reserved"), "{reserved}");
    }

    #[test]
    fn cname_target_derives_from_the_tracking_base_url() {
        assert_eq!(
            cname_target_from_base_url("https://track.apexmail.ee").as_deref(),
            Some("track.apexmail.ee")
        );
        assert_eq!(
            cname_target_from_base_url("https://Track.Example.COM:8443/base").as_deref(),
            Some("track.example.com")
        );
        assert_eq!(cname_target_from_base_url("not a url"), None);
    }

    #[test]
    fn normalise_strips_root_dot_and_case() {
        assert_eq!(
            normalise_tracking_domain(" Email.Example.COM. "),
            "email.example.com"
        );
    }

    /// POST /v1/tracking-domains without the entitlement is refused with the
    /// named plan reason (the canonical RuntimeEnforced gate, no transitional
    /// seam).
    #[tokio::test]
    async fn create_requires_the_custom_tracking_domain_entitlement() {
        let Some(pool) = crate::test_db::canonical_pool("td_gate").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool.clone(), &["domains:write"]).await;
        let (status, body) = env
            .post(
                "/v1/tracking-domains",
                r#"{"domain":"email.customer.test"}"#,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an unentitled tenant must be refused, got {status} {body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("custom_tracking_domain") || message.contains("plan"),
            "the refusal must name the missing capability/plan: {message}"
        );
    }

    /// The full lifecycle: create → records → verify (injected DNS) →
    /// verified; deletion removes the row and stops serving (the tracking
    /// service resolves only verified rows).
    #[tokio::test]
    async fn entitled_tenant_lifecycle_create_records_verify_delete() {
        let Some(pool) = crate::test_db::canonical_pool("td_lifecycle").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["domains:write", "domains:read"]).await;
        seed_entitled_plan(&pool, &tenant, "pro").await;
        seed_verified_domain(&pool, &tenant, "customer.test").await;

        let (status, created) = env
            .post(
                "/v1/tracking-domains",
                r#"{"domain":"email.customer.test"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["status"], "pending");
        assert_eq!(created["parent_domain"], "customer.test");
        let id = created["id"].as_str().expect("created id").to_string();
        let target = created["cname_target"]
            .as_str()
            .expect("cname target")
            .to_string();
        assert!(!target.is_empty());

        let (status, records) = env
            .get(&format!("/v1/tracking-domains/{id}/dns-records"))
            .await;
        assert_eq!(status, StatusCode::OK, "{records}");
        let record = &records["records"][0];
        assert_eq!(record["record_type"], "CNAME");
        assert_eq!(record["hostname"], "email.customer.test");
        assert_eq!(record["value"], target);

        // The state machine with deterministic DNS: the custom host resolves
        // to the SAME address as the CNAME target → verified.
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let mut answers = HashMap::new();
        answers.insert("email.customer.test".to_string(), Ok(vec![ip(10)]));
        answers.insert(target.clone(), Ok(vec![ip(10)]));
        let verified = verify_tracking_domain_with_dns(&state, &tenant, &id, &FakeDns { answers })
            .await
            .expect("verification runs");
        let verified = verified.0;
        assert_eq!(verified.status, "verified", "{verified:?}");
        assert!(verified.verified_at.is_some());
        assert!(verified.status_reason.is_none());

        // Mismatching DNS is stored as FAILED with the named reason.
        let mut answers = HashMap::new();
        answers.insert("email.customer.test".to_string(), Ok(vec![ip(11)]));
        answers.insert(target.clone(), Ok(vec![ip(10)]));
        let failed = verify_tracking_domain_with_dns(&state, &tenant, &id, &FakeDns { answers })
            .await
            .expect("verification runs");
        let failed = failed.0;
        assert_eq!(failed.status, "failed");
        let reason = failed.status_reason.unwrap_or_default();
        assert!(
            reason.contains("email.customer.test") && reason.contains(&target),
            "the failure names the host and the target: {reason}"
        );

        // Mutations are audit-logged.
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 \
             AND action IN ('tracking_domain.created','tracking_domain.verified','tracking_domain.verification_failed')",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("audit probe");
        assert!(
            audits >= 3,
            "expected create+verify+failure audit rows, got {audits}"
        );

        let (status, _) = env.delete(&format!("/v1/tracking-domains/{id}")).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = env.get(&format!("/v1/tracking-domains/{id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Tenant isolation: another tenant can neither read nor mutate the row,
    /// and the delete is not entitlement-gated (cleanup after a downgrade).
    #[tokio::test]
    async fn tracking_domains_are_tenant_isolated_and_delete_is_ungated() {
        let Some(pool) = crate::test_db::canonical_pool("td_iso").await else {
            return;
        };
        let (owner_env, owner) =
            AdvEnv::tenant(pool.clone(), &["domains:write", "domains:read"]).await;
        seed_entitled_plan(&pool, &owner, "pro").await;
        seed_verified_domain(&pool, &owner, "owner.test").await;
        let (status, created) = owner_env
            .post("/v1/tracking-domains", r#"{"domain":"email.owner.test"}"#)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().unwrap().to_string();

        let (other_env, other) =
            AdvEnv::tenant(pool.clone(), &["domains:write", "domains:read"]).await;
        seed_entitled_plan(&pool, &other, "pro").await;

        let (status, _) = other_env.get(&format!("/v1/tracking-domains/{id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "cross-tenant read must 404");
        let (status, _) = other_env
            .post(&format!("/v1/tracking-domains/{id}/verify"), "{}")
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-tenant verify must 404"
        );
        let (status, _) = other_env
            .delete(&format!("/v1/tracking-domains/{id}"))
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-tenant delete must 404"
        );
        let (status, list) = other_env.get("/v1/tracking-domains").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().map(Vec::len), Some(0));

        // A tenant WITHOUT the entitlement can still delete its own row.
        let (plain_env, plain) = AdvEnv::tenant(pool.clone(), &["domains:write"]).await;
        seed_verified_domain(&pool, &plain, "plain.test").await;
        let plain_id = seed_tracking_row(
            &pool,
            &plain,
            "email.plain.test",
            "plain.test",
            "pending",
            "track.apexmail.ee",
        )
        .await;
        let (status, _) = plain_env
            .delete(&format!("/v1/tracking-domains/{plain_id}"))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "cleanup must not be gated");
    }

    /// The documented policy: strict subdomain of a VERIFIED domain, one per
    /// parent and host, reserved labels refused — every refusal named.
    #[tokio::test]
    async fn tracking_domain_policy_refusals_are_named() {
        let Some(pool) = crate::test_db::canonical_pool("td_policy").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["domains:write"]).await;
        seed_entitled_plan(&pool, &tenant, "pro").await;
        seed_verified_domain(&pool, &tenant, "customer.test").await;

        // Apex of an owned domain is not a subdomain.
        let (status, body) = env
            .post("/v1/tracking-domains", r#"{"domain":"customer.test"}"#)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("subdomain"),
            "{body}"
        );

        // A host under an unowned domain.
        let (status, body) = env
            .post("/v1/tracking-domains", r#"{"domain":"email.foreign.test"}"#)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Reserved first label.
        let (status, body) = env
            .post("/v1/tracking-domains", r#"{"domain":"www.customer.test"}"#)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body.to_string().contains("reserved"),
            "the validation details must name the reserved label: {body}"
        );

        // First create succeeds; a second host for the same parent is a 409.
        let (status, first) = env
            .post(
                "/v1/tracking-domains",
                r#"{"domain":"email.customer.test"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{first}");
        let (status, body) = env
            .post(
                "/v1/tracking-domains",
                r#"{"domain":"click.customer.test"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("already has"),
            "{body}"
        );
    }

    /// A DNS outage is a 503 that leaves the stored state untouched (never a
    /// false "failed" verdict). The `.test` TLD never resolves.
    #[tokio::test]
    async fn verify_reports_a_dns_outage_as_503_without_state_change() {
        let Some(pool) = crate::test_db::canonical_pool("td_dns_down").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["domains:write", "domains:read"]).await;
        seed_entitled_plan(&pool, &tenant, "pro").await;
        seed_verified_domain(&pool, &tenant, "customer.test").await;
        let (status, created) = env
            .post(
                "/v1/tracking-domains",
                r#"{"domain":"email.customer.test"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().unwrap().to_string();

        let (status, _) = env
            .post(&format!("/v1/tracking-domains/{id}/verify"), "{}")
            .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "an unresolvable host is an outage, not a silent failed state"
        );
        let (status, row) = env.get(&format!("/v1/tracking-domains/{id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            row["status"], "pending",
            "state must not change on an outage"
        );
    }

    /// DNS resolution failure for the TARGET is also a 503 (state kept).
    #[tokio::test]
    async fn verify_with_unresolvable_target_keeps_state() {
        let Some(pool) = crate::test_db::canonical_pool("td_target_down").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("advt", 20);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
             VALUES ($1, 'n', $1, 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");
        seed_verified_domain(&pool, &tenant, "customer.test").await;
        let id = seed_tracking_row(
            &pool,
            &tenant,
            "email.customer.test",
            "customer.test",
            "pending",
            "track.apexmail.ee",
        )
        .await;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let mut answers = HashMap::new();
        answers.insert("email.customer.test".to_string(), Ok(vec![ip(10)]));
        // No answer for track.apexmail.ee → outage.
        let result =
            verify_tracking_domain_with_dns(&state, &tenant, &id, &FakeDns { answers }).await;
        let error = result.expect_err("an unresolvable target must 503");
        assert!(
            matches!(error, ApiError::ServiceUnavailable(_)),
            "{error:?}"
        );
        let status: String = sqlx::query_scalar(
            "SELECT status FROM tracking_domains WHERE id = $1 AND tenant_id = $2",
        )
        .bind(Uuid::parse_str(&id).unwrap())
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("status probe");
        assert_eq!(status, "pending");
    }
}
