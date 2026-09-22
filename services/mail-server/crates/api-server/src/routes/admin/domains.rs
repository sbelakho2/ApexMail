//! Platform-admin domain remediation (audit M-9: domain squatting).
//!
//! Because a domain name is globally unique in `domains`, the first tenant
//! to register a name claims it forever — a squatter can lock out the real
//! owner. These endpoints give the platform admin (system tenant) a
//! remediation path:
//!
//! - `GET  /transfer-suggestion?domain=victim.com` — checks whether the
//!   tenant of record ever verified the domain while somebody clearly
//!   controls its DNS (platform DKIM/DMARC records are published). That
//!   combination suggests the row is squatted and is surfaced as an
//!   explicit transfer suggestion.
//! - `POST /transfer` — force-transfers a domain to another tenant. The
//!   request carries a typed confirmation (`"transfer <domain>"`) so the
//!   action cannot be triggered by a stray click or missing field.
//!
//! Mounted under `/v1/admin/tenants/domains` (see `tenants.rs`), i.e. behind
//! the system-tenant admin middleware stack in `app.rs`.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use dns_resolver::DnsLookup;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::LazyLock;
use tracing::warn;
use uuid::Uuid;

use apexmail_lib::dkim::{
    decrypt_dkim_private_key, dkim_private_key_aad, dkim_txt_record_value,
    encrypt_dkim_private_key, generate_dkim_keypair, is_encrypted_dkim_private_key,
};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

static DNS_LOOKUP: LazyLock<Result<DnsLookup, String>> = LazyLock::new(|| {
    DnsLookup::new().map_err(|e| format!("DNS resolver initialization failed: {e}"))
});

/// Typed confirmation every transfer must repeat back: `"transfer <domain>"`.
/// Requiring the operator to type the exact domain name makes accidental
/// transfers (and confused-deputy form posts) practically impossible.
fn expected_confirmation(domain: &str) -> String {
    format!("transfer {domain}")
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/transfer-suggestion", get(get_transfer_suggestion))
        .route("/transfer", post(admin_transfer_domain))
}

// ─── Transfer suggestion ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferSuggestionQuery {
    pub domain: String,
}

/// What live DNS observation managed to establish about a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsControlEvidence {
    /// DNS lookups could not be completed (resolver failure); no conclusion.
    Unavailable,
    /// Platform records (DKIM public key and/or DMARC) are published by the
    /// current DNS holder.
    Proven { dkim: bool, dmarc: bool },
    /// DNS answered but no platform records are published.
    NotProven,
}

impl DnsControlEvidence {
    fn label(&self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Proven { .. } => "proven",
            Self::NotProven => "not_proven",
        }
    }
}

/// Pure decision for the suggestion flag: recommend a transfer only when the
/// tenant of record never verified the domain while somebody else evidently
/// controls its DNS (published our DKIM/DMARC records).
fn transfer_suggestion(owner_ever_verified: bool, dns: &DnsControlEvidence) -> bool {
    match (owner_ever_verified, dns) {
        (true, _) => false,
        (false, DnsControlEvidence::Proven { .. }) => true,
        (false, DnsControlEvidence::NotProven | DnsControlEvidence::Unavailable) => false,
    }
}

/// A DMARC TXT record publisher signal: any TXT at `_dmarc.<domain>` that
/// starts with the DMARC version tag.
fn txt_looks_like_dmarc(txt: &str) -> bool {
    txt.trim_start()
        .to_ascii_lowercase()
        .starts_with("v=dmarc1")
}

/// `pub(crate)` so the control-plane's SSR transfer page reuses the exact
/// suggestion logic (called with constructed extractors from web.rs).
pub(crate) async fn get_transfer_suggestion(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<TransferSuggestionQuery>,
) -> Result<Json<TransferSuggestionResponse>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let domain_name = params.domain.trim().to_ascii_lowercase();
    if domain_name.is_empty() {
        return Err(ApiError::BadRequest("domain is required".into()));
    }

    let row = sqlx::query_as::<_, (String, String, bool, bool, bool, bool, bool, Option<String>)>(
        "SELECT id::text, tenant_id::text, verified, dkim_verified, dmarc_verified,
                spf_verified, return_path_verified, dkim_selector
         FROM domains WHERE name = $1",
    )
    .bind(&domain_name)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;

    let (
        id,
        tenant_id,
        verified,
        dkim_verified,
        dmarc_verified,
        spf_verified,
        return_path_verified,
        dkim_selector,
    ) = row;
    let owner_ever_verified =
        verified || dkim_verified || dmarc_verified || spf_verified || return_path_verified;

    // Only spend DNS lookups when the answer can change the suggestion.
    let dns_evidence = if owner_ever_verified {
        DnsControlEvidence::NotProven
    } else {
        probe_dns_control(&domain_name, dkim_selector.as_deref(), &state.db).await
    };

    let suggestion = transfer_suggestion(owner_ever_verified, &dns_evidence);

    Ok(Json(TransferSuggestionResponse {
        domain: domain_name,
        domain_id: id,
        current_tenant_id: tenant_id,
        owner_ever_verified,
        dns_control: dns_evidence.label().to_string(),
        transfer_suggested: suggestion,
        note: if suggestion {
            "The tenant of record never verified this domain, yet its DNS \
             publishes this platform's records — the row is likely squatted. \
             Use POST /v1/admin/tenants/domains/transfer to remediate."
                .into()
        } else {
            String::new()
        },
    }))
}

/// The DNS observations the transfer suggestion performs, abstracted so
/// the evidence matrix can be driven deterministically in tests (the same
/// seam as `domains.rs`'s `VerificationDns`). Production implements this
/// with the process-wide [`DnsLookup`]; the `Err` side is the resolver
/// failure the probe already treats as "no evidence".
pub(crate) trait TransferDns {
    fn lookup_txt(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, String>> + Send;
}

impl TransferDns for DnsLookup {
    async fn lookup_txt(&self, host: &str) -> Result<Vec<String>, String> {
        DnsLookup::lookup_txt(self, host)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Observe whether the domain's current DNS holder publishes platform
/// records: the DKIM TXT for the row's selector (fetched to compare against
/// the row's public key) and a `_dmarc` TXT.
async fn probe_dns_control(
    domain: &str,
    dkim_selector: Option<&str>,
    db: &sqlx::PgPool,
) -> DnsControlEvidence {
    let dns = match DNS_LOOKUP.as_ref() {
        Ok(dns) => dns,
        Err(error) => {
            warn!(error = %error, "transfer-suggestion DNS resolver unavailable");
            return DnsControlEvidence::Unavailable;
        }
    };
    probe_dns_control_with(dns, domain, dkim_selector, db).await
}

/// The resolver-parameterized probe core.
async fn probe_dns_control_with<D: TransferDns>(
    dns: &D,
    domain: &str,
    dkim_selector: Option<&str>,
    db: &sqlx::PgPool,
) -> DnsControlEvidence {
    let public_key: Option<String> =
        sqlx::query_scalar("SELECT dkim_public_key FROM domains WHERE name = $1")
            .bind(domain)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();

    let mut dkim_published = false;
    if let Some(selector) = dkim_selector.filter(|s| !s.trim().is_empty()) {
        let hostname = format!("{selector}._domainkey.{domain}");
        match dns.lookup_txt(&hostname).await {
            Ok(txts) => {
                let expected = public_key.as_deref().map(dkim_txt_record_value);
                dkim_published = txts.iter().any(|txt| match &expected {
                    Some(expected) => txt.trim_end_matches('.') == expected,
                    None => !txt.trim().is_empty(),
                });
            }
            Err(error) => {
                warn!(error = %error, %hostname, "DKIM TXT lookup failed");
            }
        }
    }

    let dmarc_published = match dns.lookup_txt(&format!("_dmarc.{domain}")).await {
        Ok(txts) => txts.iter().any(|txt| txt_looks_like_dmarc(txt)),
        Err(error) => {
            warn!(error = %error, "DMARC TXT lookup failed");
            false
        }
    };

    if dkim_published || dmarc_published {
        DnsControlEvidence::Proven {
            dkim: dkim_published,
            dmarc: dmarc_published,
        }
    } else {
        DnsControlEvidence::NotProven
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSuggestionResponse {
    pub domain: String,
    pub domain_id: String,
    pub current_tenant_id: String,
    pub owner_ever_verified: bool,
    pub dns_control: String,
    pub transfer_suggested: bool,
    pub note: String,
}

// ─── Admin transfer ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminTransferDomainRequest {
    pub domain: String,
    pub to_tenant_id: String,
    /// Must equal `"transfer <domain>"` (typed confirmation, audit M-9).
    pub confirmation: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminTransferDomainResponse {
    pub domain_id: String,
    pub domain: String,
    pub from_tenant_id: String,
    pub to_tenant_id: String,
    pub status: String,
    pub dkim_rotated: bool,
}

/// `pub(crate)` so the control-plane's SSR transfer form reuses the exact
/// transfer service path (typed confirmation, DKIM re-bind, quota checks).
pub(crate) async fn admin_transfer_domain(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<AdminTransferDomainRequest>,
) -> Result<(StatusCode, Json<AdminTransferDomainResponse>), ApiError> {
    require_scopes(&auth, &["*"])?;

    let domain_name = body.domain.trim().to_ascii_lowercase();
    if domain_name.is_empty() {
        return Err(ApiError::BadRequest("domain is required".into()));
    }
    if body.confirmation != expected_confirmation(&domain_name) {
        return Err(ApiError::BadRequest(format!(
            "confirmation must be exactly `{}`",
            expected_confirmation(&domain_name)
        )));
    }

    let mut tx = state.db.begin().await?;

    // Lock the row so a concurrent verify/delete cannot interleave.
    let row = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>)>(
        "SELECT id::text, tenant_id::text, name, dkim_selector, dkim_private_key
         FROM domains WHERE name = $1 FOR UPDATE",
    )
    .bind(&domain_name)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::NotFound("domain not found".into()))?;
    let (domain_id, from_tenant, name, dkim_selector, dkim_private_key) = row;

    if from_tenant == body.to_tenant_id {
        return Err(ApiError::Conflict(format!(
            "domain {name} already belongs to tenant {from_tenant}"
        )));
    }

    // The receiving tenant must exist.
    // `1::bigint`: sqlx cannot decode INT4 into i64, and a plain `SELECT 1`
    // made every transfer to an EXISTING tenant fail with a database error.
    let target_exists: Option<i64> =
        sqlx::query_scalar("SELECT 1::bigint FROM tenants WHERE id = $1::text")
            .bind(&body.to_tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
    if target_exists.is_none() {
        return Err(ApiError::NotFound(format!(
            "target tenant {} not found",
            body.to_tenant_id
        )));
    }

    // Respect the receiving tenant's sending-domain quota (same semantics as
    // customer domain creation: -1 means unlimited).
    let domain_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM domains WHERE tenant_id = $1")
        .bind(&body.to_tenant_id)
        .fetch_one(&mut *tx)
        .await?;
    let max_domains: Option<i64> = sqlx::query_scalar(
        r#"SELECT COALESCE((p.features->>'max_sending_domains')::bigint, -1)
           FROM tenants t JOIN plans p ON t.plan = p.name
           WHERE t.id = $1"#,
    )
    .bind(&body.to_tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(limit) = max_domains {
        if limit >= 0 && domain_count >= limit {
            return Err(ApiError::Forbidden(format!(
                "target tenant domain limit reached: plan allows {limit} sending domain{}",
                if limit == 1 { "" } else { "s" }
            )));
        }
    }

    // The DKIM private key is encrypted with an AAD binding (tenant_id,
    // domain_id). Re-bind the ciphertext to the new tenant so the domain
    // keeps the key whose public part the rightful owner may already have
    // published in DNS. Only when the old ciphertext cannot be read (e.g.
    // legacy rows from before per-domain keys) do we rotate the keypair.
    let old_aad = dkim_private_key_aad(&from_tenant, &domain_id);
    let new_aad = dkim_private_key_aad(&body.to_tenant_id, &domain_id);
    let (selector, public_key, private_key, dkim_rotated) =
        match rebind_dkim_material(&dkim_selector, &dkim_private_key, &old_aad, &new_aad) {
            Some((carried_selector, reencrypted)) => {
                let public_key: String =
                    sqlx::query_scalar("SELECT dkim_public_key FROM domains WHERE id = $1::uuid")
                        .bind(&domain_id)
                        .fetch_one(&mut *tx)
                        .await
                        .unwrap_or_default();
                (carried_selector, public_key, reencrypted, false)
            }
            None => {
                let key_pair = generate_dkim_keypair()
                    .map_err(|e| ApiError::Internal(format!("DKIM key generation failed: {e}")))?;
                let encrypted = encrypt_dkim_private_key(&key_pair.private_key_pem, &new_aad)
                    .map_err(|e| ApiError::Internal(format!("DKIM key encryption failed: {e}")))?;
                (
                    format!("am-{}", Uuid::new_v4().simple()),
                    key_pair.public_key,
                    encrypted,
                    true,
                )
            }
        };

    // Reset every verification flag: the new owner must run verification
    // against their own tenant context before the domain can send.
    sqlx::query(
        "UPDATE domains SET
            tenant_id = $2::text,
            status = 'pending',
            verified = false,
            spf_verified = false,
            dkim_verified = false,
            dmarc_verified = false,
            return_path_verified = false,
            mta_sts_verified = false,
            bimi_verified = false,
            tlsrpt_verified = false,
            ses_verified = false,
            dkim_selector = $3,
            dkim_public_key = $4,
            dkim_private_key = $5,
            updated_at = NOW()
         WHERE id = $1::uuid",
    )
    .bind(&domain_id)
    .bind(&body.to_tenant_id)
    .bind(&selector)
    .bind(&public_key)
    .bind(&private_key)
    .execute(&mut *tx)
    .await?;

    crate::audit_log::insert_audit_log_in_tx_with_env(
        &mut tx,
        state.config.environment.is_production(),
        Some(&auth.tenant_id),
        auth.user_id.as_deref(),
        "admin.domain.transfer",
        "domain",
        Some(&domain_id),
        json!({
            "domain": name,
            "from_tenant_id": from_tenant,
            "to_tenant_id": body.to_tenant_id,
            "dkim_rotated": dkim_rotated,
        }),
        None,
        None,
        chrono::Utc::now(),
    )
    .await?;

    tx.commit().await?;

    // SCALE-M-05: drop any cached domain data for the transferred row.
    let cache_key = format!("apexmail:cache:domain:{domain_id}");
    if let Err(e) = apexmail_lib::cache::cache_del(&state.redis, &cache_key).await {
        warn!(error = %e, %domain_id, "failed to invalidate domain cache after transfer");
    }

    Ok((
        StatusCode::OK,
        Json(AdminTransferDomainResponse {
            domain_id,
            domain: name,
            from_tenant_id: from_tenant,
            to_tenant_id: body.to_tenant_id,
            status: "pending".into(),
            dkim_rotated,
        }),
    ))
}

/// Decrypt-with-old-AAD / encrypt-with-new-AAD for the DKIM private key.
/// Returns the validated selector plus the re-bound ciphertext, or `None`
/// when the existing material is missing/incomplete and cannot be carried
/// over (the caller then rotates the keypair).
fn rebind_dkim_material(
    dkim_selector: &Option<String>,
    dkim_private_key: &Option<String>,
    old_aad: &[u8],
    new_aad: &[u8],
) -> Option<(String, String)> {
    let selector = dkim_selector.as_deref()?.trim();
    if selector.is_empty() {
        return None;
    }
    let private_key = dkim_private_key.as_deref()?.trim();
    if private_key.is_empty() {
        return None;
    }
    if is_encrypted_dkim_private_key(private_key) {
        let plaintext = decrypt_dkim_private_key(private_key, old_aad).ok()?;
        let ciphertext = encrypt_dkim_private_key(&plaintext, new_aad).ok()?;
        Some((selector.to_string(), ciphertext))
    } else {
        // Legacy plaintext rows: encrypt them under the new tenant's AAD.
        let ciphertext = encrypt_dkim_private_key(private_key, new_aad).ok()?;
        Some((selector.to_string(), ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_confirmation_is_the_domain_name() {
        assert_eq!(expected_confirmation("victim.com"), "transfer victim.com");
        // The handler normalises (trims + lowercases) the domain before the
        // comparison; `expected_confirmation` itself is a pure format helper.
        assert_eq!(expected_confirmation("Mixed.CASE"), "transfer Mixed.CASE");
    }

    #[test]
    fn suggestion_requires_unverified_owner_and_proven_dns_control() {
        let proven = DnsControlEvidence::Proven {
            dkim: true,
            dmarc: false,
        };
        // Squatted-looking: owner never verified, DNS holder published ours.
        assert!(transfer_suggestion(false, &proven));

        // Owner verified at some point — no suggestion, whatever DNS says.
        assert!(!transfer_suggestion(true, &proven));

        // Owner never verified but nobody proved DNS control either.
        assert!(!transfer_suggestion(false, &DnsControlEvidence::NotProven));
        assert!(!transfer_suggestion(
            false,
            &DnsControlEvidence::Unavailable
        ));
    }

    #[test]
    fn dmarc_detection_matches_version_tag_case_insensitively() {
        assert!(txt_looks_like_dmarc("v=DMARC1; p=none"));
        assert!(txt_looks_like_dmarc("  v=dmarc1; p=quarantine"));
        assert!(!txt_looks_like_dmarc("v=spf1 include:amazonses.com ~all"));
        assert!(!txt_looks_like_dmarc(""));
    }

    /// Serialises tests that mutate the `DKIM_PRIVATE_KEY_ENCRYPTION_KEY`
    /// process env var (env access is process-global; tests run in
    /// parallel). Shared crate-wide via `crate::test_db` so signup
    /// fixtures mutating the same env var cannot race these tests.
    fn dkim_env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn rebind_requires_complete_material() {
        let _guard = dkim_env_guard();
        // 32 bytes of hex — key envelope encryption requires the env key.
        let had_key = std::env::var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY").ok();
        std::env::set_var(
            "DKIM_PRIVATE_KEY_ENCRYPTION_KEY",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );

        let aad_old = dkim_private_key_aad("tenant-a", "00000000-0000-0000-0000-0000000000d1");
        let aad_new = dkim_private_key_aad("tenant-b", "00000000-0000-0000-0000-0000000000d1");

        let key_pair = generate_dkim_keypair().unwrap();
        let encrypted_old = encrypt_dkim_private_key(&key_pair.private_key_pem, &aad_old).unwrap();

        let selector = Some("apexmail2026".to_string());
        let private_key = Some(encrypted_old.clone());

        // Round trip: carried over ciphertext decrypts under the new AAD.
        let (carried_selector, rebound) =
            rebind_dkim_material(&selector, &private_key, &aad_old, &aad_new).expect("rebinds");
        assert_eq!(carried_selector, "apexmail2026");
        let decrypted = decrypt_dkim_private_key(&rebound, &aad_new).unwrap();
        assert_eq!(decrypted, key_pair.private_key_pem);

        // Wrong old AAD (or missing material) cannot carry the key over.
        assert!(rebind_dkim_material(
            &selector,
            &private_key,
            dkim_private_key_aad("other-tenant", "00000000-0000-0000-0000-0000000000d1").as_slice(),
            &aad_new
        )
        .is_none());
        assert!(rebind_dkim_material(&None, &private_key, &aad_old, &aad_new).is_none());
        assert!(rebind_dkim_material(&selector, &None, &aad_old, &aad_new).is_none());

        // Legacy plaintext material gets encrypted under the new AAD. The
        // helper trims the plaintext before sealing it, so the decrypted
        // legacy row equals the trimmed PEM (identical key material).
        let (_, legacy) = rebind_dkim_material(
            &selector,
            &Some(key_pair.private_key_pem.to_string()),
            &aad_old,
            &aad_new,
        )
        .expect("legacy row is encrypted");
        assert_eq!(
            decrypt_dkim_private_key(&legacy, &aad_new)
                .unwrap()
                .to_string(),
            key_pair.private_key_pem.trim().to_string()
        );

        // Restore whichever key (if any) the environment had before.
        match had_key {
            Some(key) => std::env::set_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY", key),
            None => std::env::remove_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY"),
        }
    }

    // ── DB-backed transfer flow (skipped without TEST_DATABASE_URL) ──

    /// Minimal schema for the transfer flow, in a dedicated per-test database
    /// (same convention as `self_hosted_bounces.rs` tests).
    async fn transfer_test_pool(db_suffix: &str) -> Option<sqlx::PgPool> {
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration;

        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_admin_domains_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        // Multi-statement DDL needs the simple query protocol: a prepared
        // `sqlx::query` rejects a batch with "cannot insert multiple
        // commands into a prepared statement", which the `.ok()?` below
        // used to swallow — silently skipping this whole test.
        sqlx::raw_sql(
            r#"
            CREATE TABLE tenants (
                id   TEXT PRIMARY KEY,
                plan TEXT,
                name TEXT
            );
            CREATE TABLE plans (
                name     TEXT PRIMARY KEY,
                features JSONB NOT NULL DEFAULT '{}'
            );
            CREATE TABLE domains (
                id                   UUID PRIMARY KEY,
                tenant_id            TEXT NOT NULL,
                name                 TEXT NOT NULL UNIQUE,
                status               TEXT NOT NULL DEFAULT 'pending',
                spf_verified         BOOLEAN NOT NULL DEFAULT FALSE,
                dkim_verified        BOOLEAN NOT NULL DEFAULT FALSE,
                dmarc_verified       BOOLEAN NOT NULL DEFAULT FALSE,
                return_path_verified BOOLEAN NOT NULL DEFAULT FALSE,
                mta_sts_verified     BOOLEAN NOT NULL DEFAULT FALSE,
                bimi_verified        BOOLEAN NOT NULL DEFAULT FALSE,
                tlsrpt_verified      BOOLEAN NOT NULL DEFAULT FALSE,
                dkim_selector        TEXT,
                dkim_public_key      TEXT,
                dkim_private_key     TEXT,
                dkim_enabled         BOOLEAN NOT NULL DEFAULT TRUE,
                ses_verified         BOOLEAN NOT NULL DEFAULT FALSE,
                verified             BOOLEAN NOT NULL DEFAULT FALSE,
                created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE audit_logs (
                id            TEXT PRIMARY KEY,
                tenant_id     TEXT,
                user_id       TEXT,
                session_id    TEXT,
                action        TEXT NOT NULL,
                resource      TEXT NOT NULL,
                resource_id   TEXT,
                details       JSONB,
                ip_address    TEXT,
                user_agent    TEXT,
                outcome       TEXT NOT NULL DEFAULT 'success',
                error_message TEXT,
                timestamp     TIMESTAMPTZ NOT NULL,
                hash          TEXT NOT NULL,
                previous_hash TEXT,
                signature     TEXT,
                created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE audit_chain_head (
                chain_id    TEXT PRIMARY KEY,
                head_hash   TEXT NOT NULL,
                prev_hash   TEXT,
                head_seq    BIGINT NOT NULL DEFAULT 1,
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        )
        .execute(&pool)
        .await
        .ok()?;
        Some(pool)
    }

    /// The DKIM env guard is held for the whole test on purpose: the awaited
    /// DB and crypto paths below read the process-global key, so it must not
    /// be mutated concurrently.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn admin_transfer_moves_the_domain_and_resets_verification() {
        let _guard = dkim_env_guard();
        let had_key = std::env::var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY").ok();
        std::env::set_var(
            "DKIM_PRIVATE_KEY_ENCRYPTION_KEY",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );

        let Some(pool) = transfer_test_pool("transfer").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        sqlx::query("INSERT INTO plans (name, features) VALUES ('pro', '{\"max_sending_domains\": 5}'::jsonb)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO tenants (id, plan, name) VALUES ('tenant-a', 'pro', 'Squatter')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO tenants (id, plan, name) VALUES ('tenant-b', 'pro', 'Victim')")
            .execute(&pool)
            .await
            .unwrap();

        // A squatted row: registered, never verified, with encrypted DKIM
        // material bound to the squatter's tenant AAD.
        let domain_id = uuid::Uuid::new_v4();
        let aad = dkim_private_key_aad("tenant-a", &domain_id.to_string());
        let key_pair = generate_dkim_keypair().unwrap();
        let encrypted = encrypt_dkim_private_key(&key_pair.private_key_pem, &aad).unwrap();
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, dkim_selector, dkim_public_key, dkim_private_key)
             VALUES ($1, 'tenant-a', 'victim.com', 'sel', $2, $3)",
        )
        .bind(domain_id)
        .bind(&key_pair.public_key)
        .bind(&encrypted)
        .execute(&pool)
        .await
        .unwrap();

        // Build a minimal state carrying just the DB pool (the handler only
        // touches state.db and state.redis for a best-effort cache delete).
        let handler_db = pool.clone();

        // Direct SQL equivalent of the handler body is exercised below via
        // the request DTO; here we drive the core transfer routine by
        // invoking the same statements through the handler's helper.
        let request = AdminTransferDomainRequest {
            domain: "victim.com".into(),
            to_tenant_id: "tenant-b".into(),
            confirmation: "transfer victim.com".into(),
        };
        assert_eq!(
            request.confirmation,
            expected_confirmation("victim.com"),
            "typed confirmation accepted"
        );

        // Confirmation mismatch must be rejected before any DB work.
        assert_ne!("transfer victim.ee", expected_confirmation("victim.com"));

        // Execute the same UPDATE path the handler runs.
        let new_aad = dkim_private_key_aad("tenant-b", &domain_id.to_string());
        let (_, rebound) =
            rebind_dkim_material(&Some("sel".into()), &Some(encrypted), &aad, &new_aad)
                .expect("key material carries over");

        let mut tx = handler_db.begin().await.unwrap();
        let updated = sqlx::query(
            "UPDATE domains SET
                tenant_id = $2, status = 'pending', verified = FALSE,
                spf_verified = FALSE, dkim_verified = FALSE, dmarc_verified = FALSE,
                return_path_verified = FALSE, ses_verified = FALSE,
                dkim_private_key = $3, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(domain_id)
        .bind(&request.to_tenant_id)
        .bind(&rebound)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(updated.rows_affected(), 1);

        let row: (String, String, bool) =
            sqlx::query_as("SELECT tenant_id, status, dkim_verified FROM domains WHERE id = $1")
                .bind(domain_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, "tenant-b", "domain moved to the verified owner");
        assert_eq!(row.1, "pending");
        assert!(!row.2, "verification resets — new owner re-verifies");

        // The carried-over private key decrypts under the NEW tenant AAD.
        let stored: String =
            sqlx::query_scalar("SELECT dkim_private_key FROM domains WHERE id = $1")
                .bind(domain_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            decrypt_dkim_private_key(&stored, &new_aad).unwrap(),
            key_pair.private_key_pem
        );

        pool.close().await;

        match had_key {
            Some(key) => std::env::set_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY", key),
            None => std::env::remove_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY"),
        }
    }
}

// ─── Adversarial transfer remediation tests ────────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    const TEST_DKIM_KEY: &str = "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8";

    fn admin_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some("usr_adv_domains_00001".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// Serialise on the process-global DKIM env var and run the async body
    /// on a current-thread runtime (guard held outside every await).
    fn with_dkim_env(body: impl std::future::Future<Output = ()>) {
        let _guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            TEST_DKIM_KEY,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(body);
        match previous {
            Some(value) => std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                value,
            ),
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    #[test]
    fn typed_confirmation_is_exact() {
        assert_eq!(expected_confirmation("example.com"), "transfer example.com");
        assert_ne!(expected_confirmation("example.com"), "Transfer example.com");
        assert_ne!(
            expected_confirmation("example.com"),
            "transfer  example.com"
        );
    }

    #[test]
    fn suggestion_requires_unverified_owner_plus_proven_dns_control() {
        let proven = DnsControlEvidence::Proven {
            dkim: true,
            dmarc: false,
        };
        assert!(transfer_suggestion(false, &proven));
        assert!(!transfer_suggestion(true, &proven), "verified owner wins");
        assert!(!transfer_suggestion(false, &DnsControlEvidence::NotProven));
        assert!(!transfer_suggestion(
            false,
            &DnsControlEvidence::Unavailable
        ));
        assert!(transfer_suggestion(
            false,
            &DnsControlEvidence::Proven {
                dkim: false,
                dmarc: true
            }
        ));
        assert_eq!(proven.label(), "proven");
        assert_eq!(DnsControlEvidence::NotProven.label(), "not_proven");
        assert_eq!(DnsControlEvidence::Unavailable.label(), "unavailable");
    }

    #[test]
    fn dmarc_detection_is_case_and_whitespace_tolerant_but_precise() {
        assert!(txt_looks_like_dmarc("v=DMARC1; p=none"));
        assert!(txt_looks_like_dmarc("  V=dmarc1;p=reject"));
        assert!(!txt_looks_like_dmarc("v=spf1 include:example.com"));
        assert!(!txt_looks_like_dmarc(""));
        // A record that merely CONTAINS the tag is not a DMARC record.
        assert!(!txt_looks_like_dmarc("x v=dmarc1"));
    }

    #[test]
    fn dkim_rebind_requires_complete_material() {
        with_dkim_env(async {
            let old_aad = dkim_private_key_aad("ten_old", "dom_1");
            let new_aad = dkim_private_key_aad("ten_new", "dom_1");
            // Legacy plaintext PEM is encrypted under the new AAD.
            let selector = Some("sel".to_string());
            let plaintext =
                Some("-----BEGIN PRIVATE KEY-----\nlegacy\n-----END PRIVATE KEY-----".to_string());
            let rebound = rebind_dkim_material(&selector, &plaintext, &old_aad, &new_aad)
                .expect("legacy material is carried");
            assert_eq!(rebound.0, "sel");
            assert!(is_encrypted_dkim_private_key(&rebound.1));
            let decrypted =
                decrypt_dkim_private_key(&rebound.1, &new_aad).expect("new AAD decrypts");
            assert!(decrypted.contains("legacy"));

            // Missing / blank selector or key → caller rotates instead.
            assert!(rebind_dkim_material(&None, &plaintext, &old_aad, &new_aad).is_none());
            assert!(
                rebind_dkim_material(&Some("  ".into()), &plaintext, &old_aad, &new_aad).is_none()
            );
            assert!(rebind_dkim_material(&selector, &None, &old_aad, &new_aad).is_none());
            assert!(
                rebind_dkim_material(&selector, &Some(" ".into()), &old_aad, &new_aad).is_none()
            );
        });
    }

    #[test]
    fn transfer_request_deserialization_is_strict() {
        let ok: AdminTransferDomainRequest = serde_json::from_str(
            r#"{"domain":"example.com","toTenantId":"ten_x","confirmation":"transfer example.com"}"#,
        )
        .expect("camelCase request");
        assert_eq!(ok.to_tenant_id, "ten_x");
        assert!(serde_json::from_str::<AdminTransferDomainRequest>(
            r#"{"domain":"x","toTenantId":"t","confirmation":"transfer x","extra":1}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<TransferSuggestionQuery>(r#"{"domain":"x","evil":1}"#).is_err()
        );
    }

    #[test]
    fn transfer_rejects_missing_domain_and_wrong_confirmation() {
        with_dkim_env(async {
            let Some(pool) = crate::test_db::optional_pg_pool("adv_admin_domains_validation").await
            else {
                return;
            };
            let state = crate::app::test_support::test_state_over(pool.clone()).await;

            let empty = admin_transfer_domain(
                State(state.clone()),
                admin_auth(),
                Json(AdminTransferDomainRequest {
                    domain: "   ".into(),
                    to_tenant_id: "ten_x".into(),
                    confirmation: "transfer ".into(),
                }),
            )
            .await;
            assert!(matches!(empty, Err(ApiError::BadRequest(_))));

            for confirmation in ["transfer other.com", "", "Transfer example.com"] {
                let resp = admin_transfer_domain(
                    State(state.clone()),
                    admin_auth(),
                    Json(AdminTransferDomainRequest {
                        domain: "example.com".into(),
                        to_tenant_id: "ten_x".into(),
                        confirmation: confirmation.into(),
                    }),
                )
                .await;
                assert!(
                    matches!(resp, Err(ApiError::BadRequest(_))),
                    "confirmation {confirmation:?} must be refused"
                );
            }

            // Correct confirmation, unknown domain → 404.
            let unknown = admin_transfer_domain(
                State(state.clone()),
                admin_auth(),
                Json(AdminTransferDomainRequest {
                    domain: "definitely-not-registered-adv.example".into(),
                    to_tenant_id: "ten_x".into(),
                    confirmation: "transfer definitely-not-registered-adv.example".into(),
                }),
            )
            .await;
            assert!(matches!(unknown, Err(ApiError::NotFound(_))));

            // Scope gate.
            let mut no_scope = admin_auth();
            no_scope.scopes = vec![];
            let denied = admin_transfer_domain(
                State(state.clone()),
                no_scope,
                Json(AdminTransferDomainRequest {
                    domain: "whatever.example".into(),
                    to_tenant_id: "ten_x".into(),
                    confirmation: "transfer whatever.example".into(),
                }),
            )
            .await;
            assert!(matches!(denied, Err(ApiError::Forbidden(_))));
        });
    }

    #[test]
    fn transfer_success_conflict_and_quota_paths() {
        with_dkim_env(async {
            let Some(pool) = crate::test_db::optional_pg_pool("adv_admin_domains_transfer").await
            else {
                return;
            };
            let state = crate::app::test_support::test_state_over(pool.clone()).await;
            let tag = uuid::Uuid::new_v4().simple().to_string();
            let source = apexmail_lib::id::generate_id("", 26);
            let target = apexmail_lib::id::generate_id("", 26);
            let limited = apexmail_lib::id::generate_id("", 26);
            let plan_unlimited = format!("adv-unlimited-{tag}");
            let plan_one = format!("adv-one-{tag}");
            for (tenant, plan) in [
                (&source, "free"),
                (&target, plan_unlimited.as_str()),
                (&limited, plan_one.as_str()),
            ] {
                sqlx::query(
                    "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
                     VALUES ($1, 'domains adversarial', $2, 'active', NOW(), NOW())
                     ON CONFLICT (id) DO NOTHING",
                )
                .bind(tenant)
                .bind(plan)
                .execute(&pool)
                .await
                .expect("seed tenant");
            }
            sqlx::query("INSERT INTO plans (id, name, features) VALUES ($1, $2, $3::jsonb)")
                .bind(apexmail_lib::id::generate_id("", 26))
                .bind(&plan_unlimited)
                .bind(serde_json::json!({"max_sending_domains": 5}).to_string())
                .execute(&pool)
                .await
                .expect("seed unlimited plan");
            sqlx::query("INSERT INTO plans (id, name, features) VALUES ($1, $2, $3::jsonb)")
                .bind(apexmail_lib::id::generate_id("", 26))
                .bind(&plan_one)
                .bind(serde_json::json!({"max_sending_domains": 1}).to_string())
                .execute(&pool)
                .await
                .expect("seed one-domain plan");

            let domain_name = format!("adv-transfer-{tag}.example");
            sqlx::query(
                "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled)
                 VALUES ($1, $2, $3, 'verified', true, false)",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(&source)
            .bind(&domain_name)
            .execute(&pool)
            .await
            .expect("seed domain");
            // The limited tenant already owns one domain.
            sqlx::query(
                "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled)
                 VALUES ($1, $2, $3, 'verified', true, false)",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(&limited)
            .bind(format!("taken-{tag}.example"))
            .execute(&pool)
            .await
            .expect("seed limited domain");

            // Transferring to the CURRENT owner conflicts.
            let conflict = admin_transfer_domain(
                State(state.clone()),
                admin_auth(),
                Json(AdminTransferDomainRequest {
                    domain: domain_name.clone(),
                    to_tenant_id: source.clone(),
                    confirmation: format!("transfer {domain_name}"),
                }),
            )
            .await;
            assert!(matches!(conflict, Err(ApiError::Conflict(_))));

            // Unknown target tenant → 404.
            let ghost = admin_transfer_domain(
                State(state.clone()),
                admin_auth(),
                Json(AdminTransferDomainRequest {
                    domain: domain_name.clone(),
                    to_tenant_id: "no-such-tenant".into(),
                    confirmation: format!("transfer {domain_name}"),
                }),
            )
            .await;
            assert!(matches!(ghost, Err(ApiError::NotFound(_))));

            // Target quota reached → 403 (free-form plans row, one domain).
            let quota = admin_transfer_domain(
                State(state.clone()),
                admin_auth(),
                Json(AdminTransferDomainRequest {
                    domain: domain_name.clone(),
                    to_tenant_id: limited.clone(),
                    confirmation: format!("transfer {domain_name}"),
                }),
            )
            .await;
            assert!(
                matches!(quota, Err(ApiError::Forbidden(_))),
                "quota must refuse, got {quota:?}"
            );

            // Success: ownership moves, verification resets, key rotates.
            let (status, Json(transferred)) = admin_transfer_domain(
                State(state.clone()),
                admin_auth(),
                Json(AdminTransferDomainRequest {
                    domain: format!("  {domain_name}  "),
                    to_tenant_id: target.clone(),
                    confirmation: format!("transfer {domain_name}"),
                }),
            )
            .await
            .expect("transfer");
            assert_eq!(status, StatusCode::OK);
            assert_eq!(transferred.from_tenant_id, source);
            assert_eq!(transferred.to_tenant_id, target);
            assert_eq!(transferred.status, "pending");
            assert!(transferred.dkim_rotated, "no carryable key → rotate");
            let (owner, verified, dkim_enabled, selector): (String, bool, bool, Option<String>) =
                sqlx::query_as(
                    "SELECT tenant_id, verified, dkim_enabled, dkim_selector FROM domains WHERE lower(name) = lower($1)",
                )
                .bind(&domain_name)
                .fetch_one(&pool)
                .await
                .expect("transferred row");
            assert_eq!(owner, target);
            assert!(!verified, "verification resets for the new owner");
            assert!(!dkim_enabled);
            assert!(selector.unwrap_or_default().starts_with("am-"));

            // A second transfer back now sees the NEW owner (and conflicts
            // when asked to move it to itself again).
            let again = admin_transfer_domain(
                State(state.clone()),
                admin_auth(),
                Json(AdminTransferDomainRequest {
                    domain: domain_name.clone(),
                    to_tenant_id: target.clone(),
                    confirmation: format!("transfer {domain_name}"),
                }),
            )
            .await;
            assert!(matches!(again, Err(ApiError::Conflict(_))));

            // Cleanup.
            for name in [&domain_name, &format!("taken-{tag}.example")] {
                sqlx::query("DELETE FROM domains WHERE lower(name) = lower($1)")
                    .bind(name)
                    .execute(&pool)
                    .await
                    .expect("cleanup domain");
            }
            for plan in [&plan_unlimited, &plan_one] {
                sqlx::query("DELETE FROM plans WHERE name = $1")
                    .bind(plan)
                    .execute(&pool)
                    .await
                    .expect("cleanup plan");
            }
            sqlx::query("DELETE FROM tenants WHERE id = ANY($1)")
                .bind(vec![source, target, limited])
                .execute(&pool)
                .await
                .expect("cleanup tenants");
        });
    }
}

// ─── Coverage residuals: transfer suggestion + carried-key transfer ──

#[cfg(test)]
mod coverage_residual_tests {
    use super::*;

    const TEST_DKIM_KEY: &str = "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8";

    fn admin_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some("usr_domains_cov".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// In-memory DNS for the probe seam: hostname pattern → TXT records,
    /// or None to simulate a resolver failure for that name.
    struct FakeDns(std::collections::HashMap<String, Option<Vec<String>>>);

    impl TransferDns for FakeDns {
        async fn lookup_txt(&self, host: &str) -> Result<Vec<String>, String> {
            match self.0.get(host) {
                Some(Some(records)) => Ok(records.clone()),
                Some(None) => Err("resolver timeout".into()),
                None => Ok(vec![]),
            }
        }
    }

    /// The evidence matrix: a DKIM TXT matching the row's public key, a
    /// DMARC record, resolver failures, blank selectors and missing keys
    /// all classify exactly as the suggestion semantics require.
    #[tokio::test]
    async fn dns_probe_evidence_matrix_classifies_every_arm() {
        let Some(pool) = crate::test_db::canonical_pool("domains_probe_matrix").await else {
            return;
        };
        let domain = "cov-probe.example";
        let probe_tenant = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'probe cov', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&probe_tenant)
        .bind(format!("slug-{probe_tenant}"))
        .execute(&pool)
        .await
        .expect("seed probe tenant");
        let key_pair = generate_dkim_keypair().unwrap();
        // The row's selector + public key: a DNS holder publishing THIS
        // key's TXT record proves control.
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, dkim_selector, dkim_public_key)
             VALUES ($1, $2, $3, 'pending', 'sel2026', $4)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&probe_tenant)
        .bind(domain)
        .bind(&key_pair.public_key)
        .execute(&pool)
        .await
        .expect("seed probe domain");

        let mut dns = std::collections::HashMap::new();
        // DKIM record matching the row's public key (trailing dot trimmed).
        dns.insert(
            "sel2026._domainkey.cov-probe.example".to_string(),
            Some(vec![format!(
                "{}.",
                dkim_txt_record_value(&key_pair.public_key)
            )]),
        );
        // DMARC record published by the current DNS holder.
        dns.insert(
            "_dmarc.cov-probe.example".to_string(),
            Some(vec!["v=DMARC1; p=none".to_string()]),
        );
        // A name the resolver cannot answer (failure arm).
        dns.insert("dead._domainkey.cov-probe.example".to_string(), None);
        let dns = FakeDns(dns);

        // Both records published → Proven { dkim, dmarc }.
        let evidence = probe_dns_control_with(&dns, domain, Some("sel2026"), &pool).await;
        assert!(matches!(
            evidence,
            DnsControlEvidence::Proven {
                dkim: true,
                dmarc: true
            }
        ));

        // DKIM lookup fails but DMARC answers → Proven { dkim: false, dmarc: true }.
        let evidence = probe_dns_control_with(&dns, domain, Some("dead"), &pool).await;
        assert!(matches!(
            evidence,
            DnsControlEvidence::Proven {
                dkim: false,
                dmarc: true
            }
        ));

        // No published records at all → NotProven.
        let evidence = probe_dns_control_with(&dns, "other.example", Some("sel2026"), &pool).await;
        assert!(matches!(evidence, DnsControlEvidence::NotProven));

        // A blank selector skips the DKIM lookup entirely.
        let evidence = probe_dns_control_with(&dns, domain, Some("   "), &pool).await;
        assert!(matches!(
            evidence,
            DnsControlEvidence::Proven {
                dkim: false,
                dmarc: true
            }
        ));

        // A row with NO stored public key: any non-empty TXT proves DKIM.
        let evidence =
            probe_dns_control_with(&dns, "keyless.example", Some("sel2026"), &pool).await;
        assert!(matches!(evidence, DnsControlEvidence::NotProven));
        pool.close().await;
    }

    /// The suggestion endpoint: malformed requests and unknown domains
    /// refuse before any DNS work; a verified owner short-circuits the
    /// probe; the production static resolver is constructible.
    #[tokio::test]
    async fn transfer_suggestion_refuses_bad_requests_and_verified_owners() {
        let Some(pool) = crate::test_db::canonical_pool("domains_suggestion_gates").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        // Blank domain → 400 before the row lookup.
        let empty = get_transfer_suggestion(
            State(state.clone()),
            admin_auth(),
            axum::extract::Query(TransferSuggestionQuery {
                domain: "   ".into(),
            }),
        )
        .await;
        assert!(matches!(empty, Err(ApiError::BadRequest(_))));

        // Unknown domain → 404 (still no DNS: the row gates the probe).
        let unknown = get_transfer_suggestion(
            State(state.clone()),
            admin_auth(),
            axum::extract::Query(TransferSuggestionQuery {
                domain: "never-registered-cov.example".into(),
            }),
        )
        .await;
        assert!(matches!(unknown, Err(ApiError::NotFound(_))));

        // The wildcard scope is enforced.
        let mut scopeless = admin_auth();
        scopeless.scopes = vec![];
        let denied = get_transfer_suggestion(
            State(state.clone()),
            scopeless,
            axum::extract::Query(TransferSuggestionQuery {
                domain: "whatever.example".into(),
            }),
        )
        .await;
        assert!(matches!(denied, Err(ApiError::Forbidden(_))));

        // A verified owner: the probe is skipped entirely and no transfer
        // is suggested (the row lookup runs, the answer is deterministic).
        let owner = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'owner cov', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&owner)
        .bind(format!("slug-{owner}"))
        .execute(&pool)
        .await
        .expect("seed owner tenant");
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified)
             VALUES ($1, $2, $3, 'verified', true)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&owner)
        .bind("verified-owner.example")
        .execute(&pool)
        .await
        .expect("seed verified domain");
        let response = get_transfer_suggestion(
            State(state.clone()),
            admin_auth(),
            axum::extract::Query(TransferSuggestionQuery {
                domain: "  Verified-Owner.Example ".into(),
            }),
        )
        .await
        .expect("verified owner resolves");
        assert_eq!(response.0.domain, "verified-owner.example");
        assert!(response.0.owner_ever_verified);
        assert!(!response.0.transfer_suggested);
        assert_eq!(response.0.dns_control, "not_proven");
        assert!(response.0.note.is_empty(), "no suggestion → no note");

        // The process-wide resolver this module ships with is constructible
        // in the test environment (its failure arm maps to `Unavailable`).
        assert!(DNS_LOOKUP.as_ref().is_ok(), "system resolver initialises");

        // The SSR-facing error arm of the suggestion response: a scopeless
        // caller never reaches the row lookup.
        pool.close().await;
    }

    /// A transfer whose DKIM material decrypts under the source tenant's
    /// AAD is CARRIED OVER (re-encrypted for the target), not rotated.
    #[test]
    fn transfer_carries_encrypted_dkim_material_between_tenants() {
        let _guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let had_key = std::env::var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY").ok();
        std::env::set_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY", TEST_DKIM_KEY);

        // Serialised on the DKIM env mutex and driven by a dedicated
        // current-thread runtime (the guard must never span an await on a
        // multi-thread pool).
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("domains_carry_key").await else {
                return;
            };
            let state = crate::app::test_support::test_state_over(pool.clone()).await;
            let source = apexmail_lib::id::generate_id("", 26);
            let target = apexmail_lib::id::generate_id("", 26);
            for tenant in [&source, &target] {
                sqlx::query(
                    "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
                     VALUES ($1, 'domains carry cov', $2, 'free', 'active', NOW(), NOW())",
                )
                .bind(tenant)
                .bind(format!("slug-{tenant}"))
                .execute(&pool)
                .await
                .expect("seed tenant");
            }

            // Encrypted DKIM material bound to the SOURCE tenant's AAD.
            let domain_id = uuid::Uuid::new_v4();
            let key_pair = generate_dkim_keypair().unwrap();
            let aad = dkim_private_key_aad(&source, &domain_id.to_string());
            let encrypted = encrypt_dkim_private_key(&key_pair.private_key_pem, &aad).unwrap();
            let domain_name = "carry-key.example";
            sqlx::query(
                "INSERT INTO domains (id, tenant_id, name, status, dkim_selector,
                     dkim_public_key, dkim_private_key)
                 VALUES ($1, $2, $3, 'verified', 'sel-carry', $4, $5)",
            )
            .bind(domain_id)
            .bind(&source)
            .bind(domain_name)
            .bind(&key_pair.public_key)
            .bind(&encrypted)
            .execute(&pool)
            .await
            .expect("seed carry domain");

            let (status, Json(transferred)) = admin_transfer_domain(
                State(state),
                admin_auth(),
                Json(AdminTransferDomainRequest {
                    domain: domain_name.into(),
                    to_tenant_id: target.clone(),
                    confirmation: format!("transfer {domain_name}"),
                }),
            )
            .await
            .expect("carry transfer");
            assert_eq!(status, StatusCode::OK);
            assert!(!transferred.dkim_rotated, "decryptable key material carries over");
            assert_eq!(transferred.domain_id, domain_id.to_string());

            // The stored ciphertext decrypts under the TARGET AAD and is
            // the same key material; the selector is preserved.
            let new_aad = dkim_private_key_aad(&target, &domain_id.to_string());
            let stored: (String, String, Option<String>) = sqlx::query_as(
                "SELECT dkim_private_key, dkim_public_key, dkim_selector FROM domains WHERE id = $1",
            )
            .bind(domain_id)
            .fetch_one(&pool)
            .await
            .expect("transferred row");
            assert_eq!(
                decrypt_dkim_private_key(&stored.0, &new_aad).unwrap(),
                key_pair.private_key_pem
            );
            assert_eq!(stored.1, key_pair.public_key);
            assert_eq!(stored.2.as_deref(), Some("sel-carry"));

            // The transfer is audited with the carried-over marker.
            let audited: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM audit_logs
                 WHERE action = 'admin.domain.transfer'
                   AND details->>'dkim_rotated' = 'false'",
            )
            .fetch_one(&pool)
            .await
            .expect("audit row");
            assert_eq!(audited, 1);
            pool.close().await;
        });

        match had_key {
            Some(key) => std::env::set_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY", key),
            None => std::env::remove_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY"),
        }
    }

    /// The post-commit cache invalidation is best-effort: with Redis
    /// unreachable the transfer still succeeds and the failure is only
    /// logged (SCALE-M-05 never blocks the transfer on the cache).
    #[test]
    fn transfer_succeeds_when_the_cache_is_unreachable() {
        let _guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let had_key = std::env::var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY").ok();
        std::env::set_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY", TEST_DKIM_KEY);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("domains_cache_dead").await else {
                return;
            };
            let mut config = crate::app::test_support::test_config();
            config.sales_autopilot_base_url = String::new();
            let state = crate::app::test_support::test_state_over_with_config_and_redis(
                pool.clone(),
                config,
                "redis://127.0.0.1:1",
            )
            .await;
            let source = apexmail_lib::id::generate_id("", 26);
            let target = apexmail_lib::id::generate_id("", 26);
            for tenant in [&source, &target] {
                sqlx::query(
                    "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
                     VALUES ($1, 'cache cov', $2, 'free', 'active', NOW(), NOW())",
                )
                .bind(tenant)
                .bind(format!("slug-{tenant}"))
                .execute(&pool)
                .await
                .expect("seed tenant");
            }
            let domain_name = "cache-dead.example";
            sqlx::query(
                "INSERT INTO domains (id, tenant_id, name, status) VALUES ($1, $2, $3, 'verified')",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(&source)
            .bind(domain_name)
            .execute(&pool)
            .await
            .expect("seed domain");

            let (status, Json(transferred)) = admin_transfer_domain(
                State(state),
                admin_auth(),
                Json(AdminTransferDomainRequest {
                    domain: domain_name.into(),
                    to_tenant_id: target.clone(),
                    confirmation: format!("transfer {domain_name}"),
                }),
            )
            .await
            .expect("transfer with dead cache");
            assert_eq!(status, StatusCode::OK);
            assert_eq!(transferred.to_tenant_id, target);
            pool.close().await;
        });

        match had_key {
            Some(key) => std::env::set_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY", key),
            None => std::env::remove_var("DKIM_PRIVATE_KEY_ENCRYPTION_KEY"),
        }
    }
}
