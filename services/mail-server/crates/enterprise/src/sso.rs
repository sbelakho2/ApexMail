use std::sync::Once;

use chrono::{DateTime, TimeDelta, Utc};
use quick_xml::escape::escape as xml_escape;
use quick_xml::events::Event;
use quick_xml::Reader;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::compliance::ComplianceService;
use crate::config::Config;
use crate::types::*;

pub type RedisPool = deadpool_redis::Pool;

static SSO_SESSIONS_MISSING_WARNING: Once = Once::new();
const OIDC_SECRET_ENCRYPTION_PURPOSE: &str = "enterprise/sso/oidc-client-secret";

/// Tolerated clock skew between this service and the IdP when evaluating a
/// SAML assertion's `NotBefore` / `NotOnOrAfter` bounds (SAML 2.0 §2.5.1.2).
/// Applied symmetrically: an assertion may start up to 5 minutes in the
/// future and may have expired up to 5 minutes ago.
pub const SAML_CLOCK_SKEW_SECONDS: i64 = 300;

fn is_missing_relation_error(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("42P01"))
}

fn log_missing_sso_sessions_once() {
    SSO_SESSIONS_MISSING_WARNING.call_once(|| {
        tracing::warn!(
            table = "ent_sso_sessions",
            "Enterprise SSO sessions table missing; skipping session cleanup until migrations are applied"
        );
    });
}

fn xml_local_name(full_name: &str) -> &str {
    full_name.rsplit(':').next().unwrap_or(full_name)
}

// ── X.509 → SPKI extraction (minimal DER walk, no external deps) ────────────
//
// xml-sec's `verify_signature_with_pem_key` verifies with a `PUBLIC KEY`
// (SubjectPublicKeyInfo) PEM and rejects CERTIFICATE PEMs, while IdP SAML
// metadata hands us an X.509 certificate. Extract the certificate's embedded
// SubjectPublicKeyInfo so real IdP certificates verify:
//
// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
// TBSCertificate ::= SEQUENCE {
//     [0] version, serialNumber, signatureAlgorithm,
//     issuer, validity, subject, subjectPublicKeyInfo, ... }
//
// The walker only needs offsets, so it verifies tags structurally and
// borrows the SPKI bytes straight out of the input.

/// Read one DER TLV at `pos`; returns `(tag, contents, position_after)`.
fn der_tlv(buf: &[u8], pos: usize) -> Result<(u8, &[u8], usize), String> {
    let tag = *buf.get(pos).ok_or("DER: truncated tag")?;
    let mut p = pos + 1;
    let first = *buf.get(p).ok_or("DER: truncated length")?;
    p += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err("DER: unsupported length form".to_string());
        }
        let mut len = 0usize;
        for _ in 0..count {
            let byte = *buf.get(p).ok_or("DER: truncated long length")?;
            len = (len << 8) | byte as usize;
            p += 1;
        }
        len
    };
    let end = p.checked_add(len).ok_or("DER: length overflow")?;
    if end > buf.len() {
        return Err("DER: contents exceed buffer".to_string());
    }
    Ok((tag, &buf[p..end], end))
}

fn expect_tlv<'a>(
    buf: &'a [u8],
    pos: usize,
    want_tag: u8,
    context: &str,
) -> Result<(&'a [u8], usize), String> {
    let (tag, contents, end) = der_tlv(buf, pos)?;
    if tag != want_tag {
        return Err(format!(
            "DER {context}: expected tag 0x{want_tag:02x}, got 0x{tag:02x}"
        ));
    }
    Ok((contents, end))
}

/// Extract the DER SubjectPublicKeyInfo from a DER X.509 certificate.
fn spki_der_from_certificate_der(cert_der: &[u8]) -> Result<&[u8], String> {
    let (tbs_sequence, _) = expect_tlv(cert_der, 0, 0x30, "certificate")?;
    let (tbs, _) = expect_tlv(tbs_sequence, 0, 0x30, "tbsCertificate")?;
    let mut pos = 0usize;

    // Optional [0] EXPLICIT version.
    if let Some(&first) = tbs.first() {
        if first == 0xA0 {
            let (_version, end) = expect_tlv(tbs, pos, 0xA0, "version")?;
            pos = end;
        }
    }
    let (_serial, next) = expect_tlv(tbs, pos, 0x02, "serialNumber")?;
    let (_signature_algorithm, next) = expect_tlv(tbs, next, 0x30, "signature algorithm")?;
    let (_issuer, next) = expect_tlv(tbs, next, 0x30, "issuer")?;
    let (_validity, next) = expect_tlv(tbs, next, 0x30, "validity")?;
    let (_subject, next) = expect_tlv(tbs, next, 0x30, "subject")?;
    // The PUBLIC KEY PEM must carry the full SPKI element — tag and length
    // header included — not just its contents.
    let spki_start = next;
    let (_spki_contents, spki_end) = expect_tlv(tbs, next, 0x30, "subjectPublicKeyInfo")?;
    Ok(&tbs[spki_start..spki_end])
}

fn strip_pem_armor(pem: &str) -> Result<String, String> {
    let body: String = pem
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .map(|line| line.trim())
        .collect();
    if body.is_empty() {
        return Err("PEM body is empty".to_string());
    }
    Ok(body)
}

/// Build a `PUBLIC KEY` PEM from DER SubjectPublicKeyInfo bytes.
fn spki_der_to_public_key_pem(spki_der: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(spki_der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----");
    pem
}

/// Convert a certificate (PEM or base64 DER) into the SPKI `PUBLIC KEY` PEM
/// the verifier needs. A `PUBLIC KEY` block passes through unchanged.
fn public_key_pem_from_certificate(cert: &str) -> Result<String, String> {
    let trimmed = cert.trim();
    if trimmed.starts_with("-----BEGIN PUBLIC KEY-----") {
        return Ok(trimmed.to_string());
    }
    if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
        let body = strip_pem_armor(trimmed)?;
        let cert_der =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body.as_bytes())
                .map_err(|error| format!("SAML certificate base64 decode failed: {error}"))?;
        return Ok(spki_der_to_public_key_pem(spki_der_from_certificate_der(
            &cert_der,
        )?));
    }
    if trimmed.starts_with("-----BEGIN ") {
        return Err("SAML IdP certificate must be a CERTIFICATE or PUBLIC KEY PEM".to_string());
    }
    // Raw base64 DER certificate: wrap, then extract.
    let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() < 20 {
        return Err("SAML certificate is too short".to_string());
    }
    let cert_der =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, clean.as_bytes())
            .map_err(|error| format!("SAML certificate base64 decode failed: {error}"))?;
    Ok(spki_der_to_public_key_pem(spki_der_from_certificate_der(
        &cert_der,
    )?))
}

/// Verify the XML digital signature on a SAML response using the IdP's
/// certificate, and PROVE the signed-node binding (audit P2-7).
///
/// xml-sec already enforces "exactly one `<ds:Signature>` per document" and
/// digest-validity for every `<ds:Reference>`. That alone does not bind claim
/// parsing to signed content: a Reference targeting a foreign element (or a
/// Response whose wrapper stays unsigned while only an Assertion inside is
/// signed) would verify while leaving Response-level claims (Status,
/// `Destination`, `InResponseTo`, the Response Issuer) outside the signature.
/// The SAML wrapping defense is therefore strict:
///
/// * exactly ONE `<ds:Reference>` in `<SignedInfo>`, and
/// * that Reference must be the whole-document reference `URI=""` — with the
///   enveloped-signature transform, the digest then covers every byte of the
///   document except the `<ds:Signature>` itself, so every claim parsed
///   below is cryptographically bound to the verified signature.
///
/// A signature scoped to a sub-node (`URI="#_assertion1"`, xpointer, or an
/// external reference) is refused even when cryptographically valid.
fn verify_saml_document_signature(saml_xml: &str, cert_pem: &str) -> Result<(), String> {
    use xml_sec::xmldsig::verify::verify_signature_with_pem_key;
    use xml_sec::xmldsig::verify::DsigStatus;

    // The verifier requires an SPKI `PUBLIC KEY` PEM; the configured IdP
    // material is usually an X.509 CERTIFICATE (or bare base64 DER of one).
    // Extract the embedded public key so real IdP certificates verify.
    let verifying_pem = public_key_pem_from_certificate(cert_pem)?;

    let result = match verify_signature_with_pem_key(saml_xml, &verifying_pem, false) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(error = %e, "SAML XML signature verification error");
            return Err(format!("SAML XML signature verification error: {e}"));
        }
    };

    match result.status {
        DsigStatus::Valid => {}
        DsigStatus::Invalid(reason) => {
            tracing::warn!(
                failure_reason = ?reason,
                "SAML XML signature verification failed"
            );
            return Err(format!(
                "SAML XML signature verification failed: {reason:?}"
            ));
        }
        _ => {
            tracing::warn!("SAML XML signature verification returned unknown status");
            return Err("SAML XML signature verification failed: unknown status".to_string());
        }
    }

    // Signed-node binding: the claims parsed from this document are trusted
    // ONLY because the verified Reference covers the whole document.
    if result.signed_info_references.len() != 1 {
        return Err(format!(
            "SAML signature must contain exactly one ds:Reference covering the whole document, got {}",
            result.signed_info_references.len()
        ));
    }
    let reference_uri = result.signed_info_references[0].uri.as_str();
    if !reference_uri.is_empty() {
        return Err(format!(
            "SAML signature must cover the whole document (ds:Reference URI=\"\"), got URI='{reference_uri}'"
        ));
    }
    Ok(())
}

/// Configure-time half of the federation guard: an OIDC issuer the tenant
/// configures must be HTTPS unless its host is explicitly allowlisted
/// (`SSO_FEDERATION_ALLOWLIST`) — the same predicate the resolving guard
/// enforces at login begin (`federation_guard_resolved`), minus DNS.
/// Validating here turns a misconfigured issuer into an honest 400 at
/// configure time instead of a 500 every time a user opens the login page.
pub fn validate_federation_issuer_url(url_str: &str) -> Result<(), String> {
    let parsed =
        reqwest::Url::parse(url_str).map_err(|e| format!("Invalid oidc_issuer URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "oidc_issuer URL has no host".to_string())?
        .trim_matches(['[', ']']);
    if parsed.scheme() != "https" && !federation_allowlisted(host) {
        return Err(format!("oidc_issuer must use HTTPS: {url_str}"));
    }
    Ok(())
}

fn encrypt_optional_oidc_secret(
    secret: Option<&str>,
    config: &Config,
) -> Result<Option<String>, String> {
    let Some(secret) = secret.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };

    let encryptor = crate::field_encryption::encryptor_from_secret(
        &config.sso.encryption_key,
        OIDC_SECRET_ENCRYPTION_PURPOSE,
    )
    .map_err(|error| format!("Encrypt OIDC client secret: {error}"))?;

    encryptor
        .encrypt(secret)
        .map(Some)
        .map_err(|error| format!("Encrypt OIDC client secret: {error}"))
}

/// Decrypt a stored OIDC client secret for the token exchange. Rows written
/// before field-level encryption existed hold the plaintext directly; those
/// are used as-is so a pre-encryption configuration keeps working until it is
/// re-saved through [`SSOService::configure`].
fn decrypt_oidc_client_secret(stored: &str, config: &Config) -> Result<String, String> {
    if !crate::field_encryption::FieldEncryptor::is_encrypted(stored) {
        return Ok(stored.to_string());
    }
    let decryptor = crate::field_encryption::encryptor_from_secret(
        &config.sso.encryption_key,
        OIDC_SECRET_ENCRYPTION_PURPOSE,
    )
    .map_err(|error| format!("Decrypt OIDC client secret: {error}"))?;
    decryptor
        .decrypt(stored)
        .map_err(|error| format!("Decrypt OIDC client secret: {error}"))
}

// ── Outbound federation guard (audit P3-9) ──────────────────────────────
//
// OIDC is a tenant-configurable-issuer protocol: the discovery document,
// token endpoint and JWKS are all fetched from URLs a tenant admin chooses,
// which makes every one of those fetches an SSRF primitive against the
// enterprise service's network position. Every outbound federation request
// therefore goes through this guard, which reuses the log-streaming
// private/reserved-address classifier:
//
//   1. HTTPS only,
//   2. the host is resolved and ALL addresses must be public (a
//      mixed/rebinding-style answer with one private address is refused),
//   3. the resolved address is pinned into the returned client, closing the
//      validate-then-request DNS TOCTOU,
//   4. redirects are disabled — a guarded URL cannot bounce somewhere the
//      policy never evaluated,
//   5. the discovery document's `issuer` must exactly match the configured
//      issuer, and every endpoint URL it advertises is guarded the same way.
//
// `SSO_FEDERATION_ALLOWLIST` (comma-separated hosts) exists purely for local
// test infrastructure (the mock IdPs bind 127.0.0.1 over http); it never
// weakens the address check for any other host.

fn federation_allowlisted(host: &str) -> bool {
    std::env::var("SSO_FEDERATION_ALLOWLIST")
        .unwrap_or_default()
        .split(',')
        .map(|entry| entry.trim().to_lowercase())
        .filter(|entry| !entry.is_empty())
        .any(|entry| entry == host.to_lowercase())
}

/// An outbound federation URL that passed the guard, with the resolved
/// address the caller must pin its request to.
#[derive(Debug, Clone)]
pub struct FederationEndpoint {
    pub url: reqwest::Url,
    pub host: String,
    pub addr: std::net::SocketAddr,
}

/// Pure half of the guard: classify an already-resolved URL. Split from DNS
/// so the "mixed answer" case (one private address among public ones) is
/// unit-testable without a DNS override.
pub fn federation_guard_resolved(
    url_str: &str,
    ips: &[std::net::IpAddr],
) -> Result<FederationEndpoint, String> {
    let parsed = reqwest::Url::parse(url_str).map_err(|e| format!("Invalid URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "No host in URL".to_string())?
        .trim_matches(['[', ']'])
        .to_string();
    let allowlisted = federation_allowlisted(&host);
    if parsed.scheme() != "https" && !allowlisted {
        return Err(format!("Federation URL must use HTTPS: {url_str}"));
    }
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("No port in URL: {url_str}"))?;
    if ips.is_empty() {
        return Err(format!("No resolved addresses for {host}"));
    }
    for ip in ips {
        if crate::log_streaming::is_private_or_reserved_ip(*ip) && !allowlisted {
            return Err(format!(
                "Federation URL {url_str} resolves to a blocked private/reserved address ({ip})"
            ));
        }
    }
    Ok(FederationEndpoint {
        url: parsed,
        host,
        addr: std::net::SocketAddr::new(ips[0], port),
    })
}

/// Resolving federation guard — see the module-level documentation above.
pub async fn federation_guard_url(url: &str) -> Result<FederationEndpoint, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "No host in URL".to_string())?
        .trim_matches(['[', ']'])
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("No port in URL: {url}"))?;
    let ips: Vec<std::net::IpAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![ip]
    } else {
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
            .map(|socket_addr| socket_addr.ip())
            .collect()
    };
    federation_guard_resolved(url, &ips)
}

/// Build the HTTP client for a guarded endpoint: DNS pinned to the validated
/// address, redirects DISABLED (a guarded URL cannot bounce past the policy).
pub fn federation_http_client(endpoint: &FederationEndpoint) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&endpoint.host, endpoint.addr)
        .build()
        .map_err(|e| format!("Build federation client for {}: {e}", endpoint.host))
}

/// GET a JSON document through the full federation guard.
async fn federation_get_json(url: &str, what: &str) -> Result<serde_json::Value, String> {
    let endpoint = federation_guard_url(url)
        .await
        .map_err(|e| format!("{what} refused by the federation egress policy: {e}"))?;
    let client = federation_http_client(&endpoint)?;
    let response = client
        .get(endpoint.url.clone())
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("{what} request to {url} failed: {error}"))?;
    response
        .json()
        .await
        .map_err(|error| format!("{what} response from {url} was not JSON: {error}"))
}

/// POST a form body to a guarded endpoint and parse the JSON response.
async fn federation_post_form_json(
    url: &str,
    what: &str,
    form: &[(String, String)],
) -> Result<serde_json::Value, String> {
    let endpoint = federation_guard_url(url)
        .await
        .map_err(|e| format!("{what} refused by the federation egress policy: {e}"))?;
    let client = federation_http_client(&endpoint)?;
    let response = client
        .post(endpoint.url.clone())
        .form(form)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("{what} request to {url} failed: {error}"))?;
    response
        .json()
        .await
        .map_err(|error| format!("{what} response from {url} was not JSON: {error}"))
}

/// Parse a REQUIRED SAML timestamp (audit P2-8 fail-closed): a missing or
/// malformed instant is a hard refusal, never a skip. Accepts the two shapes
/// IdPs actually emit (RFC 3339 and `%Y-%m-%dT%H:%M:%S%:z`).
fn parse_required_saml_time(value: &str, what: &str) -> Result<DateTime<Utc>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("SAML {what} is missing (fail-closed)"));
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            chrono::DateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%:z")
                .map(|dt| dt.with_timezone(&Utc))
        })
        .map_err(|_| format!("SAML {what} is malformed: '{trimmed}' (fail-closed)"))
}

/// SSO Service:SAML 2.0 + OIDC authentication
pub struct SSOService {
    db: PgPool,
    redis: Option<RedisPool>,
    config: Config,
}

/// The outcome of resolving a validated federation identity onto the
/// canonical `users` table (audit P1-3).
struct ResolvedSsoUser {
    user_id: String,
    role: String,
    is_new_user: bool,
}

/// A validated federation identity (audit P1-3): the claim values both the
/// SAML ACS and the OIDC callback funnel into session issuance.
pub struct FederationIdentity<'a> {
    pub email: &'a str,
    pub display_name: Option<&'a str>,
    pub external_user_id: &'a str,
    pub groups: Option<serde_json::Value>,
    pub attributes: Option<serde_json::Value>,
}

/// The canonical-session JWT claim shape — byte-compatible with
/// `crate::middleware::auth::JwtClaims` in the api-server, which is what
/// decodes `am_session` cookies.
#[derive(Debug, serde::Serialize)]
struct CanonicalJwtClaims {
    sub: String,
    tenant_id: String,
    scopes: Vec<String>,
    exp: i64,
    iat: i64,
    jti: String,
    typ: Option<String>,
}

/// Canonical scopes per role — mirrors the api-server web login's
/// `scopes_for_role` so an SSO session carries the same authority a password
/// session of the same role would.
fn canonical_scopes_for_role(role: &str) -> Vec<String> {
    match role {
        "admin" | "owner" => vec!["*".to_string()],
        "developer" => vec![
            "messages:send",
            "messages:read",
            "domains:read",
            "templates:read",
            "templates:write",
            "events:read",
            "analytics:read",
            "contacts:read",
            "contacts:write",
            "logs:read",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        "viewer" => vec![
            "messages:send",
            "messages:read",
            "domains:read",
            "templates:read",
            "events:read",
            "analytics:read",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        _ => vec![
            "messages:send",
            "messages:read",
            "domains:read",
            "templates:read",
            "events:read",
            "analytics:read",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    }
}

/// Sanitize a post-login redirect target (same rules as the console
/// login's `safe_return_to`): relative paths only, no protocol-relative or
/// backslash hosts, no control characters, no `..` traversal. Everything
/// else falls back to `/dashboard`.
fn sanitize_return_to(return_to: Option<&str>) -> String {
    let Some(candidate) = return_to.map(str::trim).filter(|c| !c.is_empty()) else {
        return "/dashboard".to_string();
    };
    if candidate.chars().any(char::is_control) {
        return "/dashboard".to_string();
    }
    if !candidate.starts_with('/') {
        return "/dashboard".to_string();
    }
    let second = candidate.as_bytes().get(1).copied().unwrap_or(b'\0');
    if second == b'/' || second == b'\\' {
        return "/dashboard".to_string();
    }
    if candidate.split('/').any(|segment| segment == "..") {
        return "/dashboard".to_string();
    }
    candidate.to_string()
}

/// A syntactically usable OIDC email claim: exactly one `@`, non-empty local
/// part and domain, no whitespace, bounded length. (Audit P3-12: `sub` never
/// silently becomes the email.)
pub(crate) fn valid_oidc_email(raw: &str) -> bool {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 254 {
        return false;
    }
    let Some((local, domain)) = raw.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if raw.split('@').count() != 2 {
        return false;
    }
    if raw.chars().any(char::is_whitespace) {
        return false;
    }
    domain.contains('.')
}

/// Email-domain assurance (audit P3-12): the validated email must belong to
/// the SSO configuration's own domain, unless the configuration carries an
/// EXPLICIT allowed-domain mapping (`attribute_mapping.allowed_domains`).
pub(crate) fn email_belongs_to_sso_domain(email: &str, config: &SSOConfiguration) -> bool {
    let Some(domain) = email.rsplit('@').next() else {
        return false;
    };
    let domain = domain.to_ascii_lowercase();
    let configured = config.domain.trim().to_ascii_lowercase();
    if !configured.is_empty() && domain == configured {
        return true;
    }
    config
        .attribute_mapping
        .as_ref()
        .and_then(|mapping| mapping.get("allowed_domains"))
        .and_then(|value| value.as_array())
        .map(|allowed| {
            allowed
                .iter()
                .filter_map(|value| value.as_str())
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .any(|value| value == domain)
        })
        .unwrap_or(false)
}

/// The ONE identity-trust bar for a federation-asserted email — the exact
/// gate the OIDC callback has enforced since audit P3-12, now (audit F2)
/// also applied by the SAML ACS: a syntactically valid email that belongs to
/// the SSO configuration's own domain (or an explicit `allowed_domains`
/// mapping). Both federations resolve sessions through
/// [`SSOService::resolve_or_provision_sso_user`], whose first-link fallback
/// binds the IdP-asserted email to an EXISTING same-tenant account and
/// inherits its role — an unassured email is a JIT account-linking hijack.
///
/// `Err(reason)` is a policy refusal (HTTP 401), never an infrastructure
/// failure. An opaque SAML NameID (`abc123`, no `@`) can never pass: it is
/// an `external_user_id`, never an email.
pub(crate) fn validate_asserted_email(
    raw: &str,
    config: &SSOConfiguration,
) -> Result<String, String> {
    let email = raw.trim();
    if !valid_oidc_email(email) {
        return Err(
            "the assertion must carry a valid email address; an opaque identifier is never used as an email"
                .to_string(),
        );
    }
    if !email_belongs_to_sso_domain(email, config) {
        return Err("the asserted email does not belong to the configured SSO domain".to_string());
    }
    Ok(email.to_string())
}

/// The SAML shape of the OIDC `email_verified` claim (audit F2): an IdP that
/// ASSERTS a verification flag must not assert it false. SAML has no
/// standardized verified attribute, so `None` (absent) is accepted; any
/// attribute that is not a true-ish value refuses the assertion.
pub(crate) fn asserted_email_flag_is_verified(raw: Option<&str>) -> bool {
    match raw.map(str::trim).map(str::to_ascii_lowercase) {
        None => true,
        Some(value) => matches!(value.as_str(), "true" | "1" | "yes"),
    }
}

/// Fetch an IdP's discovery document through the outbound federation guard.
async fn fetch_oidc_discovery(issuer: &str) -> Result<serde_json::Value, String> {
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    federation_get_json(&discovery_url, "OIDC discovery").await
}

/// F7 (audit): reusable per-tenant `enforce_sso` lookup for api-server's
/// auth gate.
///
/// `SELECT COALESCE(bool_or(enabled AND enforce_sso), FALSE) FROM
/// ent_sso_configurations WHERE tenant_id = $1` — deterministic by
/// construction (audit P1-2): a tenant may hold a configuration row PER
/// DOMAIN, and the previous `LIMIT 1` pick was an arbitrary one of them. The
/// aggregate answers the policy question directly: SSO is enforced when ANY
/// enabled configuration row for the tenant demands it.
///
/// Contract:
/// * `Ok(true)`  — an enabled configuration row sets `enforce_sso = true`;
///   password logins for this tenant must be rejected.
/// * `Ok(false)` — no row, or no enabled row with `enforce_sso = true`:
///   password logins allowed.
/// * `Ok(false)` — the table itself is absent (`42P01`, migrations not yet
///   applied): the gate degrades open rather than locking every tenant out.
/// * `Err`       — any other database failure (surfaced so the caller can
///   fail closed on infrastructure errors).
pub async fn tenant_enforces_sso(db: &PgPool, tenant_id: &str) -> Result<bool, String> {
    match sqlx::query_scalar::<_, bool>(
        "SELECT COALESCE(bool_or(enabled AND enforce_sso), FALSE)
         FROM ent_sso_configurations WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(db)
    .await
    {
        Ok(enforced) => Ok(enforced),
        Err(sqlx::Error::Database(db_error)) if db_error.code().as_deref() == Some("42P01") => {
            Ok(false)
        }
        Err(error) => Err(format!("Check enforce_sso for tenant {tenant_id}: {error}")),
    }
}

impl SSOService {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            db,
            redis: None,
            config,
        }
    }

    /// F7: per-tenant SSO enforcement via this service's pool — see
    /// [`tenant_enforces_sso`] for the exact semantics.
    pub async fn tenant_enforces_sso(&self, tenant_id: &str) -> Result<bool, String> {
        tenant_enforces_sso(&self.db, tenant_id).await
    }

    pub fn with_redis(db: PgPool, redis: RedisPool, config: Config) -> Self {
        Self {
            db,
            redis: Some(redis),
            config,
        }
    }

    /// Configure SSO for a tenant (SAML or OIDC)
    pub async fn configure(
        &self,
        req: SSOConfigureRequest,
    ) -> Result<ApiResult<SSOConfiguration>, String> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let enabled = req.enabled.unwrap_or(true);
        let enforce = req.enforce_sso.unwrap_or(false);
        let session_hours = req.session_duration_hours.unwrap_or(8);
        let encrypted_oidc_secret =
            encrypt_optional_oidc_secret(req.oidc_client_secret.as_deref(), &self.config)?;

        let row = sqlx::query_as::<_, SSOConfiguration>(
            "INSERT INTO ent_sso_configurations (id, tenant_id, provider_type, enabled, domain, idp_entity_id, sso_url, certificate, oidc_client_id, oidc_client_secret_encrypted, oidc_issuer, attribute_mapping, enforce_sso, session_duration_hours, created_at, updated_at, allow_idp_initiated)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15, false)
             ON CONFLICT (tenant_id, domain) DO UPDATE SET
               provider_type=$3, enabled=$4, idp_entity_id=$6, sso_url=$7, certificate=$8,
                             oidc_client_id=$9, oidc_client_secret_encrypted=COALESCE($10, ent_sso_configurations.oidc_client_secret_encrypted), oidc_issuer=$11,
               attribute_mapping=$12, enforce_sso=$13, session_duration_hours=$14, updated_at=$15
             RETURNING *"
        )
           .bind(id).bind(&req.tenant_id).bind(&req.provider_type).bind(enabled)
        .bind(&req.domain).bind(&req.idp_entity_id).bind(&req.sso_url).bind(&req.certificate)
                .bind(&req.oidc_client_id).bind(&encrypted_oidc_secret).bind(&req.oidc_issuer)
        .bind(&req.attribute_mapping).bind(enforce).bind(session_hours).bind(now)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Configure SSO: {e}"))?;

        info!(tenant_id = %req.tenant_id, provider = %req.provider_type, "SSO configured");
        Ok(ApiResult::ok(row))
    }

    /// Get SSO configuration for a tenant
    pub async fn get_configuration(
        &self,
        tenant_id: &str,
    ) -> Result<ApiResult<SSOConfiguration>, String> {
        let row = sqlx::query_as::<_, SSOConfiguration>(
            "SELECT * FROM ent_sso_configurations WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get SSO config: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("SSO not configured", "NOT_FOUND")),
        }
    }

    /// Get SSO configuration by domain
    ///
    /// Audit F11: the lookup is case-INSENSITIVE. Configurations are saved
    /// verbatim, while RelayState / path domains arrive from browsers and IdP
    /// redirects — an `Example.com` row was unreachable via `example.com`,
    /// silently breaking the login flow.
    pub async fn get_config_by_domain(
        &self,
        domain: &str,
    ) -> Result<Option<SSOConfiguration>, String> {
        match sqlx::query_as::<_, SSOConfiguration>(
            "SELECT * FROM ent_sso_configurations WHERE LOWER(domain) = LOWER($1) AND enabled = true",
        )
        .bind(domain)
        .fetch_optional(&self.db)
        .await
        {
            Ok(config) => Ok(config),
            Err(sqlx::Error::Database(db_error)) if db_error.code().as_deref() == Some("42P01") => {
                Ok(None)
            }
            Err(error) => Err(format!("Get config by domain: {error}")),
        }
    }

    /// Initiate SAML login — returns redirect URL.
    ///
    /// Audit P2-4: the AuthnRequest `<saml:Issuer>` identifies APEXMAIL (the
    /// SP — `SAML_ENTITY_ID`), never the IdP; the configured `idp_entity_id`
    /// is what we ACCEPT on responses, not what we send. Audit P2-6: the
    /// freshly minted request id is durably staged in
    /// `ent_saml_authn_requests` so the ACS can correlate (and atomically
    /// consume) the response's `InResponseTo` — unsolicited responses are
    /// refused unless the tenant allows IdP-initiated logins.
    pub async fn initiate_saml_login(
        &self,
        domain: &str,
        return_to: Option<&str>,
    ) -> Result<ApiResult<SSOLoginRedirect>, String> {
        let config = self.get_config_by_domain(domain).await?;
        let config = match config {
            Some(c) if c.provider_type == "saml" => c,
            _ => {
                return Ok(ApiResult::err(
                    "SAML not configured for domain",
                    "NOT_FOUND",
                ))
            }
        };

        let request_id = format!("_saml_{}", Uuid::new_v4());
        let sso_url = config.sso_url.unwrap_or_default();
        // SP entity id: APEXMAIL itself. (config.idp_entity_id is the IdP's.)
        let sp_entity_id = self.config.sso.saml.entity_id.clone();
        let acs_url = self.config.sso.saml.acs_url.clone();

        // Stage the request for InResponseTo correlation (10-minute window).
        sqlx::query(
            "INSERT INTO ent_saml_authn_requests (request_id, tenant_id, domain, return_to, expires_at)
             VALUES ($1, $2, $3, $4, NOW() + INTERVAL '10 minutes')",
        )
        .bind(&request_id)
        .bind(&config.tenant_id)
        .bind(domain)
        .bind(return_to)
        .execute(&self.db)
        .await
        .map_err(|e| format!("Stage SAML AuthnRequest: {e}"))?;

        // Build a SAML AuthnRequest XML document with proper XML escaping
        // to prevent XML injection attacks. All user-controlled values are
        // passed through xml_escape() before interpolation.
        let issue_instant = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let saml_request_xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{}</saml:Issuer></samlp:AuthnRequest>"#,
            xml_escape(&request_id),
            xml_escape(&issue_instant),
            xml_escape(&sso_url),
            xml_escape(&acs_url),
            xml_escape(&sp_entity_id)
        );
        let saml_request_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            saml_request_xml.as_bytes(),
        );

        // RelayState carries the tenant domain: the IdP echoes it back to the
        // ACS verbatim, which lets a deployment point `SAML_ACS_URL` at the
        // domain-less `POST /sso/acs` endpoint and still resolve the tenant
        // configuration (the per-domain `POST /sso/acs/:domain` route takes
        // the domain from the path instead). `request_id` remains in the
        // returned [`SSOLoginRedirect`] for the initiator to correlate.
        let redirect_url = format!(
            "{}?SAMLRequest={}&RelayState={}",
            sso_url,
            urlencoding::encode(&saml_request_b64),
            urlencoding::encode(domain)
        );

        info!(domain = domain, request_id = %request_id, "SAML login initiated");
        Ok(ApiResult::ok(SSOLoginRedirect {
            redirect_url,
            request_id,
        }))
    }

    /// Handle SAML callback — validate assertion and create session.
    ///
    /// The tenant's SSO configuration row is passed in by the ACS handler
    /// (audit P1-2): the session lifetime comes from THAT row's
    /// `session_duration_hours`, never from a re-queried by-tenant lookup
    /// that is nondeterministic across multiple domain rows.
    pub async fn handle_saml_callback(
        &self,
        config: &SSOConfiguration,
        identity: FederationIdentity<'_>,
        return_to: Option<&str>,
    ) -> Result<ApiResult<SSOCallbackResult>, String> {
        self.issue_sso_session(config, "saml", identity, return_to)
            .await
    }

    /// Initiate OIDC login — returns authorization redirect URL.
    ///
    /// Audit P3-10: the authorize URL comes from the IdP's DISCOVERY document
    /// (`authorization_endpoint`), not a hardcoded `{issuer}/authorize`, and
    /// is fetched through the outbound federation guard (audit P3-9). The
    /// query string is assembled with the URL API's typed pair writer — never
    /// string concatenation. A single-use `state` (with the PKCE verifier and
    /// the post-login redirect target) is staged in Redis with GETDEL-backed
    /// consumption, or the durable table when Redis is absent.
    pub async fn initiate_oidc_login(
        &self,
        domain: &str,
        return_to: Option<&str>,
    ) -> Result<ApiResult<SSOLoginRedirect>, String> {
        let config = self.get_config_by_domain(domain).await?;
        let config = match config {
            Some(c)
                if c.provider_type == "oidc"
                    || c.provider_type == "okta"
                    || c.provider_type == "azure_ad"
                    || c.provider_type == "google" =>
            {
                c
            }
            _ => {
                return Ok(ApiResult::err(
                    "OIDC not configured for domain",
                    "NOT_FOUND",
                ))
            }
        };

        let issuer = config
            .oidc_issuer
            .clone()
            .map(|issuer| issuer.trim_end_matches('/').to_string())
            .filter(|issuer| !issuer.is_empty())
            .ok_or_else(|| "OIDC issuer is not configured for domain".to_string())?;
        let client_id = config.oidc_client_id.unwrap_or_default();

        // Discovery: the authorization endpoint is the IdP's own metadata
        // value, fetched through the federation egress guard.
        let discovery = fetch_oidc_discovery(&issuer).await?;
        let authorization_endpoint = discovery["authorization_endpoint"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!("OIDC discovery document from {issuer} has no authorization_endpoint")
            })?
            .to_string();

        let state = generate_random_token(32);
        let code_verifier = generate_pkce_verifier();
        let code_challenge = generate_pkce_challenge(&code_verifier);

        // Store state + code_verifier in Redis with 10-minute TTL
        if let Some(ref redis) = self.redis {
            let mut conn = redis
                .get()
                .await
                .map_err(|e| format!("Redis connection: {e}"))?;
            let key = format!("oidc_state:{}", state);
            let value = serde_json::json!({
                "code_verifier": code_verifier,
                "domain": domain,
                "tenant_id": config.tenant_id.to_string(),
                "return_to": return_to,
                "created_at": Utc::now().timestamp(),
            });
            let _: () = conn
                .set_ex(&key, value.to_string(), 600)
                .await
                .map_err(|e| format!("Redis set: {e}"))?;
        } else {
            // Fallback:store in DB for environments without Redis
            sqlx::query(
                "INSERT INTO sso_oidc_state (state, code_verifier, domain, tenant_id, return_to, expires_at)
                 VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '10 minutes')",
            )
            .bind(&state)
            .bind(&code_verifier)
            .bind(domain)
            .bind(&config.tenant_id)
            .bind(return_to)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Store OIDC state: {e}"))?;
        }

        // Typed query-pair assembly (never string concatenation).
        let redirect_url = {
            let mut url = reqwest::Url::parse(&authorization_endpoint)
                .map_err(|error| format!("Invalid authorization_endpoint URL: {error}"))?;
            url.query_pairs_mut()
                .append_pair("client_id", &client_id)
                .append_pair("redirect_uri", &self.config.sso.oidc.redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", &self.config.sso.oidc.scopes)
                .append_pair("state", &state)
                .append_pair("code_challenge", &code_challenge)
                .append_pair("code_challenge_method", "S256");
            url.to_string()
        };

        info!(domain = domain, "OIDC login initiated");
        Ok(ApiResult::ok(SSOLoginRedirect {
            redirect_url,
            request_id: state,
        }))
    }

    /// Validate and retrieve OIDC state for token exchange.
    ///
    /// Audit P3-11: the Redis path consumes the state with GETDEL — the
    /// read-and-delete is ONE atomic server operation, so two concurrent
    /// callbacks racing the same state can never both observe it.
    pub async fn validate_oidc_state(&self, state: &str) -> Result<Option<OidcStateData>, String> {
        // Try Redis first
        if let Some(ref redis) = self.redis {
            let mut conn = redis
                .get()
                .await
                .map_err(|e| format!("Redis connection: {e}"))?;
            let key = format!("oidc_state:{}", state);
            let value: Option<String> = conn
                .get_del(&key)
                .await
                .map_err(|e| format!("Redis get_del: {e}"))?;

            if let Some(json) = value {
                let parsed: serde_json::Value =
                    serde_json::from_str(&json).map_err(|e| format!("Parse state: {e}"))?;

                // #258:Return error instead of silently falling back to empty string
                let code_verifier = parsed["code_verifier"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .ok_or("Missing or empty code_verifier in OIDC state")?;

                let domain = parsed["domain"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .ok_or("Missing or empty domain in OIDC state")?;

                return Ok(Some(OidcStateData {
                    code_verifier,
                    domain,
                    tenant_id: parsed["tenant_id"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string()),
                    return_to: parsed["return_to"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string()),
                }));
            }
        }

        // Fallback:check DB (single-use via DELETE..RETURNING, atomic too)
        let row = sqlx::query_as::<_, OidcStateRow>(
            "DELETE FROM sso_oidc_state WHERE state = $1 AND expires_at > NOW() RETURNING state, code_verifier, domain, tenant_id, return_to, expires_at",
        )
        .bind(state)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get OIDC state: {e}"))?;

        Ok(row.map(|r| OidcStateData {
            code_verifier: r.code_verifier,
            domain: r.domain,
            tenant_id: Some(r.tenant_id),
            return_to: r.return_to,
        }))
    }

    /// Handle OIDC callback
    pub async fn handle_oidc_callback(
        &self,
        config: &SSOConfiguration,
        identity: FederationIdentity<'_>,
        return_to: Option<&str>,
    ) -> Result<ApiResult<SSOCallbackResult>, String> {
        self.issue_sso_session(config, "oidc", identity, return_to)
            .await
    }

    /// Complete the browser-facing half of [`Self::initiate_oidc_login`] and
    /// issue a session.
    ///
    /// 1. Consume the single-use login `state` atomically (Redis GETDEL) —
    ///    an unknown, expired or replayed state refuses the flow before any
    ///    network call.
    /// 2. Cross-check the state's tenant domain against the callback path's
    ///    `domain` (present on `GET /sso/callback/oidc/:domain`), so a state
    ///    minted for one tenant can never be redeemed on another domain's
    ///    callback.
    /// 3. Discover the IdP metadata through the outbound federation guard;
    ///    the discovery document's `issuer` must EXACTLY match the configured
    ///    issuer, and `token_endpoint` / `jwks_uri` pass the same guard.
    /// 4. Exchange `code` for tokens at the token endpoint using the PKCE
    ///    `code_verifier` persisted at initiation (plus the decrypted client
    ///    secret when one is configured). Redirects are disabled on every
    ///    federation fetch.
    /// 5. Validate the returned `id_token` against the IdP's published JWKS:
    ///    RS256 only, with the configured issuer, the configured client id as
    ///    audience, and the standard expiry checks.
    /// 6. Email assurance (audit P3-12): `sub` NEVER silently becomes the
    ///    email — a valid `email` claim is required, `email_verified` must be
    ///    true when present, and the validated email must belong to the
    ///    configured SSO domain (or an explicit `allowed_domains` mapping on
    ///    the configuration's attribute_mapping).
    /// 7. Issue an SSO session via [`Self::handle_oidc_callback`].
    ///
    /// `Ok(Ok(session))` — a session was issued. `Ok(Err(reason))` — the flow
    /// is refused (state, domain, or id_token rejected; the HTTP layer answers
    /// 401). `Err(error)` — infrastructure or upstream IdP failure (500).
    pub async fn complete_oidc_callback(
        &self,
        domain: Option<&str>,
        code: &str,
        state: &str,
        return_to: Option<&str>,
    ) -> Result<Result<SSOCallbackResult, String>, String> {
        // 1. Single-use state: unknown/expired/replayed never proceeds.
        let state_data = match self.validate_oidc_state(state).await? {
            Some(state_data) => state_data,
            None => {
                return Ok(Err(
                    "OIDC login state is invalid, expired, or already used".to_string()
                ))
            }
        };

        // 2. The state belongs to exactly one tenant domain.
        if let Some(domain) = domain {
            if state_data.domain != domain {
                tracing::warn!(
                    state_domain = %state_data.domain,
                    callback_domain = %domain,
                    "OIDC state redeemed on a foreign domain"
                );
                return Ok(Err(
                    "OIDC login state does not belong to this domain".to_string()
                ));
            }
        }
        let domain = state_data.domain.clone();

        let config = match self.get_config_by_domain(&domain).await? {
            Some(config) => config,
            None => return Ok(Err("OIDC not configured for domain".to_string())),
        };
        // The state's tenant must be the domain's tenant (a state minted for
        // one tenant can never be redeemed on another tenant's domain).
        if let Some(state_tenant) = state_data.tenant_id.as_deref() {
            if state_tenant != config.tenant_id {
                return Ok(Err(
                    "OIDC login state does not belong to this tenant".to_string()
                ));
            }
        }
        // The state's staged redirect target wins; a direct callback (state
        // without one) falls back to the caller's hint.
        let return_to = state_data
            .return_to
            .clone()
            .or_else(|| return_to.map(str::to_string));

        let issuer = config
            .oidc_issuer
            .clone()
            .map(|issuer| issuer.trim_end_matches('/').to_string())
            .filter(|issuer| !issuer.is_empty())
            .ok_or_else(|| "OIDC issuer is not configured for domain".to_string());
        let issuer = match issuer {
            Ok(issuer) => issuer,
            Err(reason) => return Ok(Err(reason)),
        };
        let client_id = config
            .oidc_client_id
            .clone()
            .filter(|client_id| !client_id.trim().is_empty())
            .ok_or_else(|| "OIDC client id is not configured for domain".to_string());
        let client_id = match client_id {
            Ok(client_id) => client_id,
            Err(reason) => return Ok(Err(reason)),
        };
        let client_secret = match config.oidc_client_secret_encrypted.as_deref() {
            Some(stored) if !stored.trim().is_empty() => {
                Some(decrypt_oidc_client_secret(stored, &self.config)?)
            }
            _ => None,
        };

        // 3. Discovery: the token endpoint and JWKS location come from the
        //    IdP's own metadata, so deployments only configure the issuer.
        //    Every fetch below goes through the federation egress guard, and
        //    the advertised issuer must match the configured one exactly.
        let discovery = match fetch_oidc_discovery(&issuer).await {
            Ok(discovery) => discovery,
            // Infrastructure-level discovery failure surfaces as 500.
            Err(error) => return Err(error),
        };
        let advertised_issuer = match discovery["issuer"]
            .as_str()
            .map(|value| value.trim_end_matches('/').to_string())
        {
            Some(advertised) => advertised,
            None => {
                return Ok(Err(format!(
                    "OIDC discovery document from {issuer} has no issuer claim"
                )))
            }
        };
        if advertised_issuer != issuer {
            return Ok(Err(format!(
                "OIDC discovery issuer mismatch: configured '{issuer}', IdP advertises '{advertised_issuer}'"
            )));
        }
        let token_endpoint = match discovery["token_endpoint"]
            .as_str()
            .filter(|value| !value.is_empty())
        {
            Some(endpoint) => endpoint.to_string(),
            None => {
                return Ok(Err(format!(
                    "OIDC discovery document from {issuer} has no token_endpoint"
                )))
            }
        };
        let jwks_uri = match discovery["jwks_uri"]
            .as_str()
            .filter(|value| !value.is_empty())
        {
            Some(uri) => uri.to_string(),
            None => {
                return Ok(Err(format!(
                    "OIDC discovery document from {issuer} has no jwks_uri"
                )))
            }
        };

        // 4. Authorization-code exchange with the persisted PKCE verifier.
        let mut form: Vec<(String, String)> = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            (
                "redirect_uri".to_string(),
                self.config.sso.oidc.redirect_uri.clone(),
            ),
            ("client_id".to_string(), client_id.clone()),
            (
                "code_verifier".to_string(),
                state_data.code_verifier.clone(),
            ),
        ];
        if let Some(secret) = &client_secret {
            form.push(("client_secret".to_string(), secret.clone()));
        }
        let token_response =
            match federation_post_form_json(&token_endpoint, "OIDC token", &form).await {
                Ok(response) => response,
                // Upstream token-endpoint failure surfaces as 500.
                Err(error) => return Err(error),
            };
        let id_token = token_response["id_token"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("OIDC token response from {token_endpoint} has no id_token"))?;

        // 5. Validate the id_token against the IdP's published keys (the
        //    JWKS document itself is fetched through the guard).
        let claims = match validate_oidc_id_token(id_token, &issuer, &client_id, &jwks_uri).await {
            Ok(claims) => claims,
            Err(reason) => return Ok(Err(reason)),
        };

        // 6. Email assurance: `sub` is the identity; the email claim must
        //    stand on its own. Syntax + domain go through the SAME gate the
        //    SAML ACS applies (`validate_asserted_email`, audit F2); the
        //    verified flag is OIDC-specific and checked here.
        let external_user_id = claims
            .get("sub")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty());
        let Some(external_user_id) = external_user_id else {
            return Ok(Err("OIDC id_token has no sub claim".to_string()));
        };
        let email = match claims
            .get("email")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
        {
            Some(raw) => match validate_asserted_email(raw, &config) {
                Ok(email) => email,
                Err(reason) => return Ok(Err(reason)),
            },
            None => return Ok(Err(
                "OIDC id_token must carry a valid email claim; the subject is never used as an email address"
                    .to_string(),
            )),
        };
        if let Some(verified) = claims.get("email_verified") {
            let verified = verified.as_bool().unwrap_or(false);
            if !verified {
                return Ok(Err(
                    "OIDC email claim is not verified by the identity provider".to_string(),
                ));
            }
        }
        let display_name = claims
            .get("name")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string);
        let groups = claims
            .get("groups")
            .and_then(|value| value.as_array())
            .cloned()
            .map(serde_json::Value::Array);

        let result = self
            .handle_oidc_callback(
                &config,
                FederationIdentity {
                    email: &email,
                    display_name: display_name.as_deref(),
                    external_user_id,
                    groups,
                    attributes: None,
                },
                return_to.as_deref(),
            )
            .await?;
        match result.data {
            Some(session) => Ok(Ok(session)),
            None => Ok(Err(result
                .error
                .unwrap_or_else(|| "OIDC session issuance failed".to_string()))),
        }
    }

    /// Issue an SSO session for a validated federation identity.
    ///
    /// Audit P1-3 — canonical session integration: the federation identity is
    /// resolved (or provisioned) onto the CANONICAL `users` table through the
    /// durable `ent_sso_identities` binding, and the same `am_session`
    /// JWT/cookie the web login issues is minted for it, so a successful SSO
    /// callback produces a REAL logged-in console session instead of only an
    /// enterprise bearer token. `ent_sso_sessions` remains as SSO audit
    /// metadata keyed to the canonical user — and stores ONLY a SHA-256
    /// digest of its bearer token (audit P1-3 hardening).
    ///
    /// `is_new_user` is identity-based: it is true exactly when no
    /// `(sso_config_id, external_user_id)` binding existed before this login,
    /// so the session-cleanup sweep can never resurrect a user as "new".
    async fn issue_sso_session(
        &self,
        config: &SSOConfiguration,
        provider_type: &str,
        identity: FederationIdentity<'_>,
        return_to: Option<&str>,
    ) -> Result<ApiResult<SSOCallbackResult>, String> {
        let FederationIdentity {
            email,
            display_name,
            external_user_id,
            groups,
            attributes,
        } = identity;
        // Identity resolution/provisioning against the canonical users table.
        let resolved = self
            .resolve_or_provision_sso_user(config, email, display_name, external_user_id)
            .await?;

        // Session lifetime from THIS configuration row (audit P1-2).
        let session_hours = config.session_duration_hours;

        let session_token = generate_random_token(64);
        let session_id = Uuid::new_v4();
        let expires_at =
            Utc::now() + TimeDelta::try_hours(session_hours as i64).unwrap_or(TimeDelta::zero());

        // Bearer tokens at rest: SHA-256 digest only. The raw token is
        // returned once (to the flow that minted it) and never persisted.
        let mut hasher = Sha256::new();
        hasher.update(session_token.as_bytes());
        let token_digest = hex::encode(hasher.finalize());

        let _session = sqlx::query_as::<_, SSOSession>(
            "INSERT INTO ent_sso_sessions (id, tenant_id, user_id, provider_type, external_user_id, email, display_name, groups, attributes, session_token, session_token_digest, expires_at, last_activity_at, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,$10,$11,NOW(),NOW())
             RETURNING *",
        )
        .bind(session_id).bind(&config.tenant_id).bind(&resolved.user_id).bind(provider_type)
        .bind(external_user_id).bind(email).bind(display_name)
        .bind(&groups).bind(&attributes).bind(&token_digest).bind(expires_at)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create SSO session: {e}"))?;

        // Canonical console session: the same am_session JWT the web login
        // issues, signed with the deployment's shared RS256 key. The lifetime
        // is THIS configuration row's `session_duration_hours` (audit F6) —
        // the same policy the enterprise row above is sized from.
        let canonical = self.mint_canonical_session(
            &resolved.user_id,
            &config.tenant_id,
            &resolved.role,
            session_hours,
            return_to,
        );

        let group_list = groups.and_then(|g| serde_json::from_value::<Vec<String>>(g).ok());

        info!(
            tenant_id = %config.tenant_id,
            user_id = %resolved.user_id,
            email = %mail_common::pii::redact_email(email),
            is_new_user = resolved.is_new_user,
            canonical_session = canonical.is_some(),
            "SSO session created"
        );

        // Audit F7: the enterprise service writes its own audit trail — a
        // federated session issuance is a security-relevant event that must
        // not depend on the client remembering to POST /compliance/audit.
        // Best-effort: an audit-write failure is logged, never blocks the
        // (fully validated) login itself.
        let audit = ComplianceService::new(self.db.clone());
        if let Err(error) = audit
            .log_audit(
                config.tenant_id.clone(),
                Some(&resolved.user_id),
                "sso_session_issued",
                "sso_session",
                Some(&session_id.to_string()),
                None,
                Some(serde_json::json!({
                    "provider": provider_type,
                    "external_user_id": external_user_id,
                    "email": mail_common::pii::redact_email(email).to_string(),
                    "is_new_user": resolved.is_new_user,
                    "session_hours": session_hours,
                    "canonical_session": canonical.is_some(),
                })),
                None,
                None,
                None,
                None,
                None,
            )
            .await
        {
            tracing::error!(error = %error, "failed to audit sso_session_issued");
        }
        Ok(ApiResult::ok(SSOCallbackResult {
            session: SSOSessionInfo {
                session_token,
                email: email.to_string(),
                display_name: display_name.map(|s| s.to_string()),
                groups: group_list,
                expires_at,
            },
            is_new_user: resolved.is_new_user,
            canonical,
        }))
    }

    /// Resolve a validated federation identity onto the canonical `users`
    /// table (audit P1-3), binding it durably in `ent_sso_identities`.
    ///
    /// Resolution order:
    /// 1. the `(sso_config_id, external_user_id)` identity link — the only
    ///    binding the IdP account holder cannot re-point,
    /// 2. an existing canonical user with the same tenant + email
    ///    (first-link fallback; SAML/OIDC emails are IdP-asserted),
    /// 3. provisioning a new canonical user INSIDE the configured tenant
    ///    (role `member`, SSO-only `$sso$` password placeholder).
    ///
    /// The resolved user must be `active`; suspended users never get a
    /// session. `is_new_user` is true exactly when the identity link had to
    /// be created on THIS login.
    async fn resolve_or_provision_sso_user(
        &self,
        config: &SSOConfiguration,
        email: &str,
        display_name: Option<&str>,
        external_user_id: &str,
    ) -> Result<ResolvedSsoUser, String> {
        // 1. Durable identity link.
        let linked: Option<(String, String, String)> = sqlx::query_as(
            "SELECT u.id::text, COALESCE(u.role, 'member'), u.status
             FROM ent_sso_identities i
             JOIN users u ON u.id = i.user_id
             WHERE i.sso_config_id = $1 AND i.external_user_id = $2
             LIMIT 1",
        )
        .bind(config.id)
        .bind(external_user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Resolve SSO identity: {e}"))?;

        let (user_id, _linked_role, is_new_identity) = match linked {
            Some((user_id, role, _status)) => (user_id, role, false),
            None => {
                // 2. First-link fallback on the (IdP-asserted) email, scoped
                // to the configured tenant.
                let matched: Option<(String, String)> = sqlx::query_as(
                    "SELECT id::text, COALESCE(role, 'member') FROM users
                     WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)
                     LIMIT 1",
                )
                .bind(&config.tenant_id)
                .bind(email)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("Match SSO user by email: {e}"))?;

                match matched {
                    Some((user_id, role)) => (user_id, role, true),
                    None => {
                        // 3. Provision inside the configured tenant.
                        let user_id = Uuid::new_v4();
                        let placeholder_hash =
                            format!("$sso${}$no-password-sso-login-only", config.provider_type);
                        sqlx::query(
                            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified, mfa_enabled, metadata, created_at, updated_at)
                             VALUES ($1, $2, $3, $4, $5, 'member', 'active', true, false, $6, NOW(), NOW())",
                        )
                        .bind(user_id)
                        .bind(&config.tenant_id)
                        .bind(email)
                        .bind(display_name)
                        .bind(&placeholder_hash)
                        .bind(serde_json::json!({
                            "sso_provider": config.provider_type,
                            "sso_external_id": external_user_id,
                        }))
                        .execute(&self.db)
                        .await
                        .map_err(|error| {
                            // users.email is UNIQUE across ALL tenants: the
                            // IdP-asserted email may exist under a DIFFERENT
                            // organization. That is a policy refusal, not an
                            // infrastructure failure — fail the login with a
                            // clear reason instead of a 500 (and never link
                            // across tenants).
                            if matches!(&error, sqlx::Error::Database(db_error)
                                if db_error.code().as_deref() == Some("23505"))
                            {
                                "SSO provisioning refused: an account with the asserted email already exists in another organization".to_string()
                            } else {
                                format!("Provision SSO user: {error}")
                            }
                        })?;
                        (user_id.to_string(), "member".to_string(), true)
                    }
                }
            }
        };

        // The identity binding is (re)written on every login; the conflict
        // arm only refreshes the login stamp, so a concurrent callback cannot
        // fail the login.
        sqlx::query(
            "INSERT INTO ent_sso_identities (sso_config_id, tenant_id, external_user_id, user_id, email, last_login_at)
             VALUES ($1, $2, $3, $4::uuid, $5, NOW())
             ON CONFLICT (sso_config_id, external_user_id)
             DO UPDATE SET last_login_at = NOW(), email = EXCLUDED.email",
        )
        .bind(config.id)
        .bind(&config.tenant_id)
        .bind(external_user_id)
        .bind(&user_id)
        .bind(email)
        .execute(&self.db)
        .await
        .map_err(|e| format!("Bind SSO identity: {e}"))?;

        // An inactive canonical user never receives a session (the identity
        // link survives, so re-activation restores SSO logins).
        let (role, status): (String, String) = sqlx::query_as(
            "SELECT COALESCE(role, 'member'), status FROM users WHERE id = $1::uuid",
        )
        .bind(&user_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Load SSO user: {e}"))?;
        if status != "active" {
            return Err(format!("SSO user account is {status}"));
        }

        Ok(ResolvedSsoUser {
            user_id,
            role,
            is_new_user: is_new_identity,
        })
    }

    /// Mint the canonical console session (`am_session`) for a resolved SSO
    /// user — the identical JWT claim shape and cookie attributes the web
    /// login (`session_cookie_for_user`) issues, signed with the deployment's
    /// shared RS256 key (`JWT_PRIVATE_KEY_PEM`).
    ///
    /// `session_hours` is the tenant's configured `session_duration_hours`
    /// (audit F6): the cookie and JWT expiry derive from the SAME policy the
    /// enterprise SSO session row uses, instead of a hardcoded 8 hours — a
    /// 1-hour configuration used to mint 8-hour console cookies (an 8× wider
    /// privilege window than policy), and a 24-hour one was silently cut to
    /// 8. Values below 1 are clamped to 1 hour (a zero/negative Max-Age would
    /// expire the cookie on arrival); values above 24h are clamped down to
    /// the historical maximum.
    ///
    /// `None` when the deployment has not configured the shared signing key:
    /// the enterprise session record still exists, but no console cookie can
    /// be minted (logged loudly — deployments wanting console SSO must set
    /// the key).
    fn mint_canonical_session(
        &self,
        user_id: &str,
        tenant_id: &str,
        role: &str,
        session_hours: i32,
        return_to: Option<&str>,
    ) -> Option<CanonicalSession> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        if self.config.jwt_private_key_pem.is_empty() {
            tracing::warn!(
                "JWT_PRIVATE_KEY_PEM is not configured; SSO login issued an enterprise session without a canonical console session"
            );
            return None;
        }

        // Session lifetime mirrors the enterprise SSO session row (F6).
        let expiry_secs: i64 = session_hours.clamp(1, 24) as i64 * 3600;
        let claims = CanonicalJwtClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            scopes: canonical_scopes_for_role(role),
            exp: (Utc::now() + TimeDelta::seconds(expiry_secs)).timestamp(),
            iat: Utc::now().timestamp(),
            jti: Uuid::new_v4().to_string(),
            typ: Some("session".to_string()),
        };
        let encoding_key = match EncodingKey::from_rsa_pem(
            self.config.jwt_private_key_pem.as_bytes(),
        ) {
            Ok(key) => key,
            Err(error) => {
                tracing::error!(error = %error, "JWT_PRIVATE_KEY_PEM is not a valid RSA private key");
                return None;
            }
        };
        let token = match encode(&Header::new(Algorithm::RS256), &claims, &encoding_key) {
            Ok(token) => token,
            Err(error) => {
                tracing::error!(error = %error, "failed to mint canonical SSO session JWT");
                return None;
            }
        };
        let secure = self.config.node_env == "production" || self.config.node_env == "prod";
        Some(CanonicalSession {
            user_id: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            cookie: format!(
                "am_session={token}; HttpOnly; Path=/; Max-Age={expiry_secs}; SameSite=Strict{}",
                if secure { "; Secure" } else { "" }
            ),
            return_to: sanitize_return_to(return_to),
        })
    }

    /// Validate session token.
    ///
    /// The presented token is hashed and matched against
    /// `session_token_digest` — the database never holds the raw bearer
    /// value (audit P1-3), so a database read cannot leak usable tokens.
    pub async fn validate_session(
        &self,
        session_token: &str,
    ) -> Result<Option<SSOSession>, String> {
        let mut hasher = Sha256::new();
        hasher.update(session_token.trim().as_bytes());
        let token_digest = hex::encode(hasher.finalize());

        let session = sqlx::query_as::<_, SSOSession>(
            "SELECT * FROM ent_sso_sessions WHERE session_token_digest = $1 AND expires_at > NOW()",
        )
        .bind(&token_digest)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Validate session: {e}"))?;

        if let Some(ref s) = session {
            if let Err(e) =
                sqlx::query("UPDATE ent_sso_sessions SET last_activity_at = NOW() WHERE id = $1")
                    .bind(s.id)
                    .execute(&self.db)
                    .await
            {
                tracing::warn!(session_id = %s.id, error = %e, "Failed to update SSO session last_activity_at");
            }
        }
        Ok(session)
    }

    /// Atomically consume a staged AuthnRequest (audit P2-6).
    ///
    /// `DELETE … WHERE request_id = $1 AND tenant_id = $2 AND expires_at >
    /// NOW() RETURNING …` is a single atomic statement: the staged request is
    /// consumed exactly once, expired stages are dead, and a request staged
    /// for another tenant never matches.
    async fn consume_saml_authn_request(
        &self,
        request_id: &str,
        tenant_id: &str,
    ) -> Result<Option<(String, Option<String>)>, String> {
        sqlx::query_as(
            "DELETE FROM ent_saml_authn_requests
             WHERE request_id = $1 AND tenant_id = $2 AND expires_at > NOW()
             RETURNING domain, return_to",
        )
        .bind(request_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Consume SAML AuthnRequest: {e}"))
    }

    /// Parse and validate a SAML response XML document (the ACS entry point).
    ///
    /// Full validation order, all fail-closed:
    /// 1. XML-DSig signature verification with SIGNED-NODE BINDING (audit
    ///    P2-7): exactly one whole-document `ds:Reference` — every claim
    ///    parsed below is cryptographically bound to the verified signature.
    /// 2. InResponseTo CORRELATION (audit P2-6): the response's
    ///    `InResponseTo` is atomically consumed from the staged
    ///    `ent_saml_authn_requests`; unsolicited responses are refused unless
    ///    the configuration explicitly allows IdP-initiated logins.
    /// 3. Claim validation against the four independent ground truths of
    ///    [`SamlValidationContext`] (audit P2-5): Response `Destination` and
    ///    SubjectConfirmationData `Recipient` == ACS URL, Assertion
    ///    `Audience` == SP entity id, Issuers == configured IdP entity id.
    /// 4. Expiration FAIL-CLOSED (audit P2-8): `NotOnOrAfter` is required,
    ///    must parse, and bounds are exclusive with clock skew.
    /// 5. Per-tenant replay guard.
    ///
    /// Returns the validated NameID, attributes and correlation metadata.
    pub async fn parse_and_validate_saml_response(
        &self,
        saml_response_xml: &str,
        domain: &str,
    ) -> Result<ValidatedSamlResponse, String> {
        let config = self
            .get_config_by_domain(domain)
            .await?
            .ok_or_else(|| "SAML not configured for domain".to_string())?;

        // 1. Signature gate (before any claim is read).
        let cert_raw = config.certificate.as_deref().ok_or_else(|| {
            tracing::warn!(
                domain = domain,
                "SAML: No IdP certificate configured — signature verification not possible"
            );
            "SAML IdP certificate is not configured; cannot verify XML signature".to_string()
        })?;
        verify_saml_document_signature(saml_response_xml, cert_raw)?;

        // 2. InResponseTo correlation against the staged request.
        let parsed = parse_saml_document(saml_response_xml)?;
        let (expected_request_id, return_to) = match parsed.response_in_response_to.as_deref() {
            Some(request_id) if !request_id.trim().is_empty() => {
                let Some((staged_domain, staged_return_to)) = self
                    .consume_saml_authn_request(request_id.trim(), &config.tenant_id)
                    .await?
                else {
                    return Err(format!(
                        "SAML InResponseTo '{request_id}' does not match an outstanding request for this tenant (unknown, expired, or already used)"
                    ));
                };
                if staged_domain != domain {
                    return Err("SAML InResponseTo does not belong to this domain".to_string());
                }
                (Some(request_id.trim().to_string()), staged_return_to)
            }
            _ => {
                if !config.allow_idp_initiated {
                    return Err(
                        "unsolicited SAML response refused (no InResponseTo): this tenant does not allow IdP-initiated login"
                            .to_string(),
                    );
                }
                (None, None)
            }
        };

        let ctx = SamlValidationContext {
            idp_entity_id: config
                .idp_entity_id
                .clone()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    "SAML IdP entity id (idp_entity_id) is not configured for domain".to_string()
                })?,
            sp_entity_id: self.config.sso.saml.entity_id.clone(),
            acs_url: self.config.sso.saml.acs_url.clone(),
            expected_request_id,
        };
        let validated = validate_parsed_saml_document(&parsed, &ctx)?;

        // 5. Replay guard — only reached after every signature and claim
        //    check above has passed, so an invalid assertion cannot burn an
        //    assertion id.
        self.validate_saml_assertion_claims(
            &config.tenant_id,
            &validated.assertion_id,
            validated.not_before,
            validated.not_on_or_after,
            Utc::now(),
        )
        .await?;

        Ok(ValidatedSamlResponse {
            return_to,
            ..validated
        })
    }

    /// Enforce a SAML assertion's validity window and replay protection.
    ///
    /// This is the post-signature half of
    /// [`Self::parse_and_validate_saml_response`], kept separate so it can be
    /// tested without an IdP-signed XML fixture:
    ///
    /// * `NotOnOrAfter` is REQUIRED (audit P2-8 fail-closed) and its bound is
    ///   EXCLUSIVE with [`SAML_CLOCK_SKEW_SECONDS`] of tolerance; `NotBefore`
    ///   is inclusive with the same skew.
    /// * `assertion_id` is consumed exactly once per `tenant_id` in
    ///   `ent_saml_assertion_replays` (idempotent `ON CONFLICT DO NOTHING`
    ///   insert); a second use of the same id is rejected as a replay. The
    ///   replay row carries the assertion's own expiry (+ skew) and the sweep
    ///   deletes only PAST-EXPIRY records, so retention always covers the
    ///   assertion's lifetime (audit P2-8).
    pub async fn validate_saml_assertion_claims(
        &self,
        tenant_id: &str,
        assertion_id: &str,
        not_before: Option<DateTime<Utc>>,
        not_on_or_after: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let assertion_id = assertion_id.trim();
        if assertion_id.is_empty() {
            return Err(
                "SAML assertion is missing an ID; it cannot be protected against replay"
                    .to_string(),
            );
        }

        let skew = TimeDelta::seconds(SAML_CLOCK_SKEW_SECONDS);

        if let Some(not_before) = not_before {
            if now + skew < not_before {
                tracing::warn!(
                    not_before = %not_before.to_rfc3339(),
                    skew_seconds = SAML_CLOCK_SKEW_SECONDS,
                    "SAML assertion is not yet valid"
                );
                return Err(format!(
                    "SAML assertion is not yet valid (NotBefore {})",
                    not_before.to_rfc3339()
                ));
            }
        }

        // Exclusive bound: at `expires` itself the assertion is already over.
        if now - skew >= not_on_or_after {
            tracing::warn!(
                expires = %not_on_or_after.to_rfc3339(),
                skew_seconds = SAML_CLOCK_SKEW_SECONDS,
                "SAML assertion has expired"
            );
            return Err(format!(
                "SAML assertion has expired (NotOnOrAfter {})",
                not_on_or_after.to_rfc3339()
            ));
        }

        // Expiry-driven retention: drop only records whose assertion is no
        // longer valid, so the store stays bounded WITHOUT ever deleting a
        // replay record that still protects a live assertion.
        sqlx::query("DELETE FROM ent_saml_assertion_replays WHERE expires_at < NOW()")
            .execute(&self.db)
            .await
            .map_err(|error| format!("Prune SAML replay store: {error}"))?;

        // Idempotent, bounded insert: ON CONFLICT DO NOTHING + RETURNING
        // distinguishes "fresh" from "already consumed" atomically.
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO ent_saml_assertion_replays (tenant_id, assertion_id, expires_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id, assertion_id) DO NOTHING
             RETURNING assertion_id",
        )
        .bind(tenant_id)
        .bind(assertion_id)
        .bind(not_on_or_after + skew)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| format!("Record SAML assertion replay guard: {error}"))?;

        if inserted.is_none() {
            tracing::warn!(
                tenant_id = tenant_id,
                assertion_id = assertion_id,
                "SAML assertion replay detected"
            );
            return Err(format!(
                "SAML assertion replay rejected: assertion {assertion_id} was already consumed for this tenant"
            ));
        }

        Ok(())
    }

    /// Cleanup expired sessions and the expired staged-AuthnRequest rows.
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, String> {
        let result = match sqlx::query("DELETE FROM ent_sso_sessions WHERE expires_at < NOW()")
            .execute(&self.db)
            .await
        {
            Ok(result) => result,
            Err(error) if is_missing_relation_error(&error) => {
                log_missing_sso_sessions_once();
                return Ok(0);
            }
            Err(error) => return Err(format!("Cleanup sessions: {error}")),
        };
        let count = result.rows_affected();
        if count > 0 {
            info!(count = count, "Cleaned up expired SSO sessions");
        }
        // Expired staged SAML requests are worthless once outlived; sweep
        // them opportunistically (missing table tolerated like sessions).
        if let Err(error) =
            sqlx::query("DELETE FROM ent_saml_authn_requests WHERE expires_at < NOW()")
                .execute(&self.db)
                .await
        {
            if !is_missing_relation_error(&error) {
                return Err(format!("Cleanup staged SAML requests: {error}"));
            }
        }
        Ok(count)
    }
}

// ── OIDC id_token validation ───────────────────────────────────────────

/// Validate an OIDC `id_token` against the IdP's published JWKS and return
/// its claims.
///
/// Security posture: RS256 only (no `alg`-switching: an id_token declaring
/// any other algorithm is refused before a key is selected), the signing key
/// is chosen by `kid` from the IdP's JWKS, the JWKS itself is fetched
/// through the outbound federation guard, and the standard issuer, audience
/// and expiry checks all apply. Returns the decoded claim set, or a refusal
/// reason for the flow to surface as a 401.
async fn validate_oidc_id_token(
    id_token: &str,
    issuer: &str,
    client_id: &str,
    jwks_uri: &str,
) -> Result<serde_json::Value, String> {
    use jsonwebtoken::jwk::JwkSet;

    let header = jsonwebtoken::decode_header(id_token)
        .map_err(|error| format!("OIDC id_token header is malformed: {error}"))?;
    if header.alg != jsonwebtoken::Algorithm::RS256 {
        return Err(format!(
            "OIDC id_token must be RS256-signed, got {:?}",
            header.alg
        ));
    }
    let kid = header
        .kid
        .filter(|kid| !kid.trim().is_empty())
        .ok_or_else(|| "OIDC id_token header is missing kid".to_string())?;

    let jwks_raw = match federation_get_json(jwks_uri, "OIDC JWKS").await {
        Ok(jwks) => jwks,
        // JWKS fetch failures are refusals (401 surface), not 500s: the IdP
        // advertised this URI in its discovery document, so its policy
        // compliance is part of the login validation.
        Err(error) => return Err(error),
    };
    let jwks: JwkSet = serde_json::from_value(jwks_raw).map_err(|error| {
        format!("OIDC JWKS response from {jwks_uri} was not a valid JWK set: {error}")
    })?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| format!("OIDC JWKS from {jwks_uri} has no signing key for kid {kid}"))?;
    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk)
        .map_err(|error| format!("OIDC JWKS key for kid {kid} is unusable: {error}"))?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);
    let data = jsonwebtoken::decode::<serde_json::Value>(id_token, &decoding_key, &validation)
        .map_err(|error| format!("OIDC id_token validation failed: {error}"))?;
    Ok(data.claims)
}

// ── PKCE helpers ───────────────────────────────────────────────────────

/// Generate a PKCE code verifier (43-128 characters, URL-safe)
pub fn generate_pkce_verifier() -> String {
    use aes_gcm::aead::rand_core::RngCore;
    let mut bytes = vec![0u8; 64];
    aes_gcm::aead::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|&b| {
            const CHARSET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._";
            CHARSET[(b as usize) % CHARSET.len()] as char
        })
        .collect()
}

/// Generate PKCE code challenge:base64url(sha256(verifier))
pub fn generate_pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash)
}

/// Generate a random hex token
pub fn generate_random_token(len: usize) -> String {
    use aes_gcm::aead::rand_core::RngCore;
    let mut bytes = vec![0u8; len];
    aes_gcm::aead::OsRng.fill_bytes(&mut bytes);
    hex::encode(&bytes)
}

// ── SAML validation types and helpers ──────────────────────────────────

/// The raw content of one parsed SAML response document. The signature
/// verification and the InResponseTo correlation both need the parse; the
/// semantic checks run afterwards against a [`SamlValidationContext`].
#[derive(Debug, Default)]
pub(crate) struct ParsedSamlDocument {
    pub response_destination: Option<String>,
    pub response_in_response_to: Option<String>,
    pub status_code: Option<String>,
    pub response_issuer: Option<String>,
    pub assertion_issuer: Option<String>,
    pub response_issuer_count: usize,
    pub assertion_issuer_count: usize,
    pub assertion_count: usize,
    pub assertion_ids: Vec<String>,
    pub audiences: Vec<String>,
    pub not_before_raw: Option<String>,
    pub not_on_or_after_raw: Option<String>,
    pub subject_confirmation_data: Vec<ParsedSubjectConfirmationData>,
    pub name_id_count: usize,
    pub name_id: Option<String>,
    pub attributes: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub(crate) struct ParsedSubjectConfirmationData {
    pub recipient: Option<String>,
    pub in_response_to: Option<String>,
    pub not_on_or_after_raw: Option<String>,
}

/// The result of a successfully validated SAML response.
#[derive(Debug)]
pub struct ValidatedSamlResponse {
    /// The validated and sanitized NameID value.
    pub name_id: String,
    /// List of (attribute_name, sanitized_value) pairs.
    pub attributes: Vec<(String, String)>,
    /// The (single) Assertion ID — the replay-protection key.
    pub assertion_id: String,
    /// Parsed `Conditions/@NotBefore` (optional).
    pub not_before: Option<DateTime<Utc>>,
    /// Parsed (required) `Conditions/@NotOnOrAfter`.
    pub not_on_or_after: DateTime<Utc>,
    /// The response's `InResponseTo` when it carried one.
    pub in_response_to: Option<String>,
    /// The consumed staged request's post-login redirect target.
    pub return_to: Option<String>,
}

/// Stream-parse a SAML response document into its raw content.
///
/// quick_xml::Reader does not resolve external entities by default
/// (inherent XXE protection); entity references arrive as separate
/// `Event::GeneralRef` events, so Text content is entity-free.
pub(crate) fn parse_saml_document(xml: &str) -> Result<ParsedSamlDocument, String> {
    let mut reader = Reader::from_str(xml);

    let mut parsed = ParsedSamlDocument::default();
    let mut current_path: Vec<String> = Vec::new();
    let mut in_status_code = false;
    let mut in_issuer: Option<bool> = None; // Some(inside_assertion) at Start
    let mut in_audience = false;
    let mut in_audience_restriction = false;
    let mut in_conditions = false;
    let mut in_name_id = false;
    let mut in_attribute = false;
    let mut in_attribute_value = false;
    let mut current_attr_name: Option<String> = None;
    let mut text_buf = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                text_buf.clear();
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let tag = xml_local_name(&name).to_string();

                match tag.as_str() {
                    "Response" if current_path.is_empty() => {
                        for attr in e.attributes().filter_map(|a| a.ok()) {
                            let value = String::from_utf8(attr.value.to_vec()).unwrap_or_default();
                            match attr.key.as_ref() {
                                b"Destination" => parsed.response_destination = Some(value),
                                b"InResponseTo" => parsed.response_in_response_to = Some(value),
                                _ => {}
                            }
                        }
                    }
                    "StatusCode" => in_status_code = true,
                    "Issuer" => {
                        let inside_assertion = current_path
                            .iter()
                            .any(|p| xml_local_name(p) == "Assertion");
                        in_issuer = Some(inside_assertion);
                        if inside_assertion {
                            parsed.assertion_issuer_count += 1;
                        } else {
                            parsed.response_issuer_count += 1;
                        }
                    }
                    "AudienceRestriction" => in_audience_restriction = true,
                    "Audience" => in_audience = in_conditions && in_audience_restriction,
                    "Assertion" => {
                        parsed.assertion_count += 1;
                        if let Some(attr) = e
                            .attributes()
                            .filter_map(|a| a.ok())
                            .find(|a| a.key.as_ref() == b"ID")
                        {
                            if let Ok(val) = String::from_utf8(attr.value.to_vec()) {
                                parsed.assertion_ids.push(val);
                            }
                        }
                    }
                    "Conditions" => {
                        in_conditions = true;
                        for attr in e.attributes().filter_map(|a| a.ok()) {
                            let value = match String::from_utf8(attr.value.to_vec()) {
                                Ok(value) => value,
                                Err(_) => continue,
                            };
                            match attr.key.as_ref() {
                                b"NotBefore" => parsed.not_before_raw = Some(value),
                                b"NotOnOrAfter" => parsed.not_on_or_after_raw = Some(value),
                                _ => {}
                            }
                        }
                    }
                    "SubjectConfirmationData" => {
                        parsed.subject_confirmation_data.push(Default::default());
                        let entry = parsed
                            .subject_confirmation_data
                            .last_mut()
                            .expect("SubjectConfirmationData just pushed");
                        for attr in e.attributes().filter_map(|a| a.ok()) {
                            let value = String::from_utf8(attr.value.to_vec()).unwrap_or_default();
                            match attr.key.as_ref() {
                                b"Recipient" => entry.recipient = Some(value),
                                b"InResponseTo" => entry.in_response_to = Some(value),
                                b"NotOnOrAfter" => entry.not_on_or_after_raw = Some(value),
                                _ => {}
                            }
                        }
                    }
                    "NameID" => {
                        in_name_id = true;
                        parsed.name_id_count += 1;
                    }
                    "Attribute" => {
                        in_attribute = true;
                        current_attr_name = e
                            .attributes()
                            .filter_map(|a| a.ok())
                            .find(|a| a.key.as_ref() == b"Name")
                            .and_then(|a| String::from_utf8(a.value.to_vec()).ok());
                    }
                    "AttributeValue" => in_attribute_value = in_attribute,
                    _ => {}
                }
                current_path.push(name);
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let tag = xml_local_name(&name).to_string();
                current_path.pop();

                match tag.as_str() {
                    "StatusCode" => in_status_code = false,
                    "Issuer" => in_issuer = None,
                    "Audience" => in_audience = false,
                    "AudienceRestriction" => in_audience_restriction = false,
                    "Conditions" => in_conditions = false,
                    "SubjectConfirmationData" => {}
                    "NameID" => in_name_id = false,
                    "Attribute" => {
                        in_attribute = false;
                        current_attr_name = None;
                    }
                    "AttributeValue" => {
                        if in_attribute_value && in_attribute {
                            if let Some(attr_name) = current_attr_name.take() {
                                let sanitized = sanitize_saml_value(&text_buf);
                                parsed.attributes.push((attr_name, sanitized));
                                text_buf.clear();
                            }
                        }
                        in_attribute_value = false;
                    }
                    _ => {}
                }
            }
            // quick-xml 0.41: `unescape()` is gone; Text events are decoded
            // via `decode()`. Entity references now arrive as separate
            // `Event::GeneralRef` events, so Text content is entity-free.
            Ok(Event::Text(ref e)) => {
                if let Ok(text) = e.decode() {
                    let text_str = text.as_ref();
                    if in_status_code {
                        parsed.status_code = Some(text_str.to_string());
                    } else if let Some(in_assertion) = in_issuer {
                        if in_assertion {
                            parsed.assertion_issuer = Some(text_str.to_string());
                        } else {
                            parsed.response_issuer = Some(text_str.to_string());
                        }
                    } else if in_audience {
                        parsed.audiences.push(text_str.to_string());
                    } else if in_name_id {
                        parsed.name_id = Some(text_str.to_string());
                    } else if in_attribute && in_attribute_value {
                        text_buf.push_str(text_str);
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let tag = xml_local_name(&name).to_string();
                if tag == "StatusCode" {
                    // Handle self-closing StatusCode with Value attribute
                    if let Some(attr) = e
                        .attributes()
                        .filter_map(|a| a.ok())
                        .find(|a| a.key.as_ref() == b"Value")
                    {
                        if let Ok(val) = String::from_utf8(attr.value.to_vec()) {
                            parsed.status_code = Some(val);
                        }
                    }
                } else if tag == "SubjectConfirmationData" {
                    // A self-closing SubjectConfirmationData carries its
                    // attributes identically — count and parse them.
                    parsed.subject_confirmation_data.push(Default::default());
                    let entry = parsed
                        .subject_confirmation_data
                        .last_mut()
                        .expect("SubjectConfirmationData just pushed");
                    for attr in e.attributes().filter_map(|a| a.ok()) {
                        let value = String::from_utf8(attr.value.to_vec()).unwrap_or_default();
                        match attr.key.as_ref() {
                            b"Recipient" => entry.recipient = Some(value),
                            b"InResponseTo" => entry.in_response_to = Some(value),
                            b"NotOnOrAfter" => entry.not_on_or_after_raw = Some(value),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                tracing::warn!(saml_parse_error = %e, "SAML XML parse error");
                return Err(format!("SAML XML parse error: {e}"));
            }
            _ => {}
        }
    }

    Ok(parsed)
}

/// Validate a parsed SAML response against the four independent ground
/// truths of the [`SamlValidationContext`] (audit P2-5), plus structural
/// hardening (audit P2-7) and fail-closed expiration (audit P2-8).
///
/// The caller must have ALREADY verified the XML-DSig signature with
/// [`verify_saml_document_signature`]: the whole-document reference binding
/// is what makes every claim below trustworthy.
pub(crate) fn validate_parsed_saml_document(
    parsed: &ParsedSamlDocument,
    ctx: &SamlValidationContext,
) -> Result<ValidatedSamlResponse, String> {
    // 1. StatusCode is success.
    let status_value = parsed.status_code.as_deref().unwrap_or("");
    if !status_value.ends_with(":Success")
        && status_value != "urn:oasis:names:tc:SAML:2.0:status:Success"
    {
        tracing::warn!(saml_status = %status_value, "SAML response StatusCode is not Success");
        return Err(format!(
            "SAML authentication failed: StatusCode is '{status_value}'"
        ));
    }

    // 2. Response/Destination == ACS URL (deconflated from the Audience).
    match parsed.response_destination.as_deref() {
        Some(destination) if destination.trim() == ctx.acs_url => {}
        Some(destination) => {
            tracing::warn!(
                saml_destination = %destination,
                expected_acs_url = %ctx.acs_url,
                "SAML Response Destination mismatch"
            );
            return Err("SAML Response Destination does not match the ACS URL".to_string());
        }
        None => return Err("SAML response is missing the Destination attribute".to_string()),
    }

    // 3. Issuer == configured IdP entity id, on BOTH the Response and the
    //    Assertion, each present exactly once (a duplicated Issuer element
    //    at either level is malformed and refused — issuer-confusion
    //    defense).
    fn clean(value: &Option<String>) -> Option<&str> {
        value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
    if parsed.response_issuer_count > 1 || parsed.assertion_issuer_count > 1 {
        return Err("SAML response contains multiple Issuer elements".to_string());
    }
    let response_issuer = clean(&parsed.response_issuer)
        .ok_or_else(|| "SAML response missing Issuer element".to_string())?;
    let assertion_issuer = clean(&parsed.assertion_issuer)
        .ok_or_else(|| "SAML assertion missing Issuer element".to_string())?;
    if response_issuer != ctx.idp_entity_id || assertion_issuer != ctx.idp_entity_id {
        tracing::warn!(
            response_issuer = %response_issuer,
            assertion_issuer = %assertion_issuer,
            expected_idp_entity_id = %ctx.idp_entity_id,
            "SAML Issuer mismatch"
        );
        return Err("SAML Issuer does not match the configured IdP entity id".to_string());
    }

    // 4. Assertion Audience == SP entity id (deconflated from Destination /
    //    Recipient). EVERY AudienceRestriction/Audience must carry it.
    if parsed.audiences.is_empty() {
        return Err("SAML response missing AudienceRestriction".to_string());
    }
    for audience in &parsed.audiences {
        if audience.trim() != ctx.sp_entity_id {
            tracing::warn!(
                saml_audience = %audience,
                expected_sp_entity_id = %ctx.sp_entity_id,
                "SAML AudienceRestriction mismatch"
            );
            return Err("SAML AudienceRestriction does not match the SP entity id".to_string());
        }
    }

    // 5. SubjectConfirmationData: exactly one bearer confirmation, whose
    //    Recipient is the ACS URL and whose InResponseTo matches the
    //    correlated request.
    if parsed.subject_confirmation_data.len() != 1 {
        return Err(format!(
            "SAML response must carry exactly one SubjectConfirmationData, got {}",
            parsed.subject_confirmation_data.len()
        ));
    }
    let scd = &parsed.subject_confirmation_data[0];
    match scd.recipient.as_deref().map(str::trim) {
        Some(recipient) if recipient == ctx.acs_url => {}
        Some(recipient) => {
            tracing::warn!(
                saml_recipient = %recipient,
                expected_acs_url = %ctx.acs_url,
                "SAML SubjectConfirmationData Recipient mismatch"
            );
            return Err(
                "SAML SubjectConfirmationData Recipient does not match the ACS URL".to_string(),
            );
        }
        None => {
            return Err(
                "SAML SubjectConfirmationData is missing the Recipient attribute".to_string(),
            )
        }
    }
    match (&scd.in_response_to, &ctx.expected_request_id) {
        (None, None) => {}
        (Some(scd_request), Some(expected)) if scd_request.trim() == expected.trim() => {}
        _ => {
            return Err(
                "SAML SubjectConfirmationData InResponseTo does not match the correlated request"
                    .to_string(),
            )
        }
    }
    // A SCD validity instant, when present, is required to parse and hold.
    let scd_expires_at = match scd.not_on_or_after_raw.as_deref() {
        Some(raw) => {
            let expires = parse_required_saml_time(raw, "SubjectConfirmationData NotOnOrAfter")?;
            let skew = TimeDelta::seconds(SAML_CLOCK_SKEW_SECONDS);
            if Utc::now() - skew >= expires {
                return Err("SAML SubjectConfirmationData NotOnOrAfter has expired".to_string());
            }
            Some(expires)
        }
        None => None,
    };
    let _ = scd_expires_at;

    // 6. Structural hardening: exactly ONE Assertion, exactly ONE NameID,
    //    no duplicate Assertion IDs (XML wrapping defense).
    if parsed.assertion_count != 1 {
        return Err(format!(
            "SAML response must contain exactly one Assertion, got {}",
            parsed.assertion_count
        ));
    }
    if parsed.name_id_count != 1 {
        return Err(format!(
            "SAML response must contain exactly one NameID, got {}",
            parsed.name_id_count
        ));
    }

    // 7. NameID present and sanitizable.
    let name_id = parsed
        .name_id
        .as_deref()
        .ok_or_else(|| "SAML response missing NameID element".to_string())?;
    let sanitized_name_id = sanitize_saml_value(name_id);
    if sanitized_name_id.is_empty() {
        tracing::warn!("SAML NameID is empty after sanitization");
        return Err("SAML NameID is empty after sanitization".to_string());
    }

    // 8. Expiration FAIL-CLOSED (audit P2-8): Conditions must carry a
    //    parseable NotOnOrAfter; bounds are exclusive-with-skew.
    if parsed.assertion_ids.iter().any(|id| id.trim().is_empty()) {
        return Err(
            "SAML assertion is missing an ID; it cannot be protected against replay".to_string(),
        );
    }
    let assertion_id = parsed.assertion_ids.first().cloned().ok_or_else(|| {
        "SAML response missing Assertion ID (required for replay protection)".to_string()
    })?;
    let not_on_or_after = match parsed.not_on_or_after_raw.as_deref() {
        Some(raw) => parse_required_saml_time(raw, "NotOnOrAfter")?,
        None => {
            return Err(
                "SAML Conditions are missing NotOnOrAfter (fail-closed: an assertion without an expiry is refused)"
                    .to_string(),
            )
        }
    };
    let skew = TimeDelta::seconds(SAML_CLOCK_SKEW_SECONDS);
    if Utc::now() - skew >= not_on_or_after {
        tracing::warn!(
            expires = %not_on_or_after.to_rfc3339(),
            skew_seconds = SAML_CLOCK_SKEW_SECONDS,
            "SAML assertion has expired"
        );
        return Err(format!(
            "SAML assertion has expired (NotOnOrAfter {})",
            not_on_or_after.to_rfc3339()
        ));
    }
    let not_before = match parsed.not_before_raw.as_deref() {
        Some(raw) => {
            let not_before = parse_required_saml_time(raw, "NotBefore")?;
            if Utc::now() + skew < not_before {
                tracing::warn!(
                    not_before = %not_before.to_rfc3339(),
                    skew_seconds = SAML_CLOCK_SKEW_SECONDS,
                    "SAML assertion is not yet valid"
                );
                return Err(format!(
                    "SAML assertion is not yet valid (NotBefore {})",
                    not_before.to_rfc3339()
                ));
            }
            Some(not_before)
        }
        None => None,
    };

    Ok(ValidatedSamlResponse {
        name_id: sanitized_name_id,
        attributes: parsed.attributes.clone(),
        assertion_id,
        not_before,
        not_on_or_after,
        in_response_to: parsed.response_in_response_to.clone(),
        return_to: None,
    })
}

/// Signature-free claim validation against an explicit context — the unit
/// test seam for the deconflation matrix (each ground truth mutated
/// independently; only correct semantics pass).
pub fn validate_saml_document_claims(
    saml_response_xml: &str,
    ctx: &SamlValidationContext,
) -> Result<ValidatedSamlResponse, String> {
    let parsed = parse_saml_document(saml_response_xml)?;
    validate_parsed_saml_document(&parsed, ctx)
}

/// Sanitize a SAML attribute or NameID value.
///
/// Rejects strings containing `<`, `>`, `&`, control characters (U+0000–U+001F
/// except U+0009, U+000A, U+000D), or exceeding 256 characters in length.
///
/// Returns the sanitized (trimmed) value on success, or an empty string if
/// the value is invalid.
fn sanitize_saml_value(value: &str) -> String {
    let trimmed = value.trim();

    // Reject empty values
    if trimmed.is_empty() {
        return String::new();
    }

    // Reject values exceeding 256 chars
    if trimmed.len() > 256 {
        tracing::warn!(
            value_length = trimmed.len(),
            "SAML value exceeds maximum length of 256 characters"
        );
        return String::new();
    }

    // Reject XML-special characters: < > &
    if trimmed.contains('<') || trimmed.contains('>') || trimmed.contains('&') {
        tracing::warn!("SAML value contains XML-special characters");
        return String::new();
    }

    // Reject control characters (except tab, newline, carriage return)
    if trimmed.chars().any(|c| {
        let code = c as u32;
        code < 0x20 && code != 0x09 && code != 0x0A && code != 0x0D
    }) {
        tracing::warn!("SAML value contains control characters");
        return String::new();
    }

    trimmed.to_string()
}

// ── Tests ──────────────────────────────────────────────────────────────
//
// `pub(crate)` items here are the shared IdP-signing fixtures reused by the
// router-level end-to-end tests in `routes.rs` (same crate, same cfg(test)).

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::Reader;

    // ── PKCE tests ────────────────────────────────────────────────

    fn is_pkce_unreserved(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
    }

    #[test]
    fn test_pkce_verifier_length() {
        let v = generate_pkce_verifier();
        assert_eq!(v.len(), 64);
        assert!(v.chars().all(is_pkce_unreserved));
    }

    #[test]
    fn test_pkce_verifier_uniqueness() {
        // Verify two verifiers generated in quick succession are different
        let v1 = generate_pkce_verifier();
        let v2 = generate_pkce_verifier();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_pkce_challenge_deterministic() {
        let v = "test_verifier_12345678901234567890";
        let c1 = generate_pkce_challenge(v);
        let c2 = generate_pkce_challenge(v);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_pkce_challenge_is_base64url() {
        let c = generate_pkce_challenge("some_verifier");
        // Base64url should not contain + or /
        assert!(!c.contains('+'));
        assert!(!c.contains('/'));
        assert!(!c.contains('='));
    }

    #[test]
    fn test_pkce_challenge_length_is_valid() {
        // SHA-256 produces 32 bytes → base64url encodes to 43 chars (no padding)
        let c = generate_pkce_challenge("test_verifier_value");
        assert_eq!(c.len(), 43);
    }

    #[test]
    fn test_pkce_full_flow_round_trip() {
        // Verify that a code verifier can generate a challenge, and that the
        // challenge is verifiable (deterministic property).
        let verifier = generate_pkce_verifier();
        let challenge1 = generate_pkce_challenge(&verifier);
        let challenge2 = generate_pkce_challenge(&verifier);
        assert_eq!(challenge1, challenge2);
        assert_ne!(challenge1, generate_pkce_challenge("different_verifier"));
    }

    #[test]
    fn test_pkce_verifier_min_length_43() {
        // RFC 7636 says verifier must be at least 43 chars.
        // Our implementation generates 64 chars which satisfies this.
        let v = generate_pkce_verifier();
        assert!(
            v.len() >= 43,
            "PKCE verifier must be ≥43 chars per RFC 7636"
        );
    }

    #[test]
    fn test_pkce_verifier_max_length_128() {
        // RFC 7636 says verifier must be at most 128 chars.
        let v = generate_pkce_verifier();
        assert!(
            v.len() <= 128,
            "PKCE verifier must be ≤128 chars per RFC 7636"
        );
    }

    #[test]
    fn test_pkce_verifier_url_safe() {
        // Verifier must contain only unreserved characters per RFC 7636
        let v = generate_pkce_verifier();
        assert!(
            v.chars().all(is_pkce_unreserved),
            "PKCE verifier must only contain unreserved characters"
        );
    }

    // ── Random token tests ─────────────────────────────────────────

    #[test]
    fn test_random_token_length() {
        let t = generate_random_token(32);
        assert_eq!(t.len(), 64); // hex doubles the byte count
    }

    #[test]
    fn test_random_token_uniqueness() {
        let t1 = generate_random_token(16);
        let t2 = generate_random_token(16);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_random_token_varying_lengths() {
        // Verify token generation works for different requested lengths.
        for len in [8, 16, 32, 64] {
            let t = generate_random_token(len);
            assert_eq!(t.len(), len * 2, "hex token length mismatch for len={len}");
        }
    }

    #[test]
    fn test_random_token_is_hex() {
        // Verify the token is valid hexadecimal.
        let t = generate_random_token(32);
        assert!(
            t.chars().all(|c| c.is_ascii_hexdigit()),
            "token must be valid hex: {t}"
        );
    }

    // ── Serde tests ───────────────────────────────────────────────

    #[test]
    fn test_sso_login_redirect_serde() {
        let r = SSOLoginRedirect {
            redirect_url: "https://idp.example.com/sso".into(),
            request_id: "req123".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("redirect_url"));
        let parsed: SSOLoginRedirect = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.request_id, "req123");
    }

    #[test]
    fn test_sso_session_info_serde() {
        let s = SSOSessionInfo {
            session_token: "tok".into(),
            email: "a@b.com".into(),
            display_name: Some("User".into()),
            groups: Some(vec!["admin".into()]),
            expires_at: Utc::now(),
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["email"], "a@b.com");
    }

    #[test]
    fn test_sso_callback_result_serde() {
        let r = SSOCallbackResult {
            session: SSOSessionInfo {
                session_token: "t".into(),
                email: "u@e.com".into(),
                display_name: None,
                groups: None,
                expires_at: Utc::now(),
            },
            is_new_user: true,
            canonical: None,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["is_new_user"], true);
    }

    #[test]
    fn test_sso_configure_request_serde() {
        let req = SSOConfigureRequest {
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
            provider_type: "saml".into(),
            domain: "example.com".into(),
            enabled: Some(true),
            idp_entity_id: Some("urn:test".into()),
            sso_url: Some("https://idp.example.com/sso".into()),
            certificate: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_issuer: None,
            attribute_mapping: None,
            enforce_sso: None,
            session_duration_hours: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("saml"));
    }

    #[test]
    fn test_oidc_state_data_serde() {
        // Verify that OidcStateData round-trips through JSON (used for Redis storage).
        let state = OidcStateData {
            code_verifier: "abc123verifier".into(),
            domain: "example.com".into(),
            tenant_id: Some("tenant_01HZ".into()),
            return_to: None,
        };
        let json = serde_json::json!({
            "code_verifier": state.code_verifier,
            "domain": state.domain,
            "tenant_id": state.tenant_id,
            "created_at": Utc::now().timestamp(),
        });
        let parsed: OidcStateData = OidcStateData {
            code_verifier: json["code_verifier"].as_str().unwrap().to_string(),
            domain: json["domain"].as_str().unwrap().to_string(),
            tenant_id: json["tenant_id"].as_str().map(|s| s.to_string()),
            return_to: None,
        };
        assert_eq!(parsed.code_verifier, "abc123verifier");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.tenant_id, Some("tenant_01HZ".into()));
    }

    #[test]
    fn test_oidc_state_data_missing_tenant_id() {
        // Verify that OidcStateData handles missing tenant_id (None).
        let state = OidcStateData {
            code_verifier: "verifier123".into(),
            domain: "company.com".into(),
            tenant_id: None,
            return_to: None,
        };
        let json = serde_json::json!({
            "code_verifier": state.code_verifier,
            "domain": state.domain,
        });
        let parsed = OidcStateData {
            code_verifier: json["code_verifier"].as_str().unwrap().to_string(),
            domain: json["domain"].as_str().unwrap().to_string(),
            tenant_id: json["tenant_id"].as_str().map(|s| s.to_string()),
            return_to: None,
        };
        assert!(parsed.tenant_id.is_none());
    }

    // ── Field encryption tests ─────────────────────────────────────

    #[test]
    fn test_encrypt_optional_oidc_secret_produces_encrypted_blob() {
        let mut config = Config::from_env().unwrap();
        config.sso.encryption_key = "enterprise-secret-material-for-tests".into();

        let encrypted = encrypt_optional_oidc_secret(Some("oidc-top-secret"), &config)
            .unwrap()
            .expect("encrypted secret");

        assert!(crate::field_encryption::FieldEncryptor::is_encrypted(
            &encrypted
        ));
        assert_ne!(encrypted, "oidc-top-secret");

        let decryptor = crate::field_encryption::encryptor_from_secret(
            &config.sso.encryption_key,
            OIDC_SECRET_ENCRYPTION_PURPOSE,
        )
        .unwrap();
        assert_eq!(decryptor.decrypt(&encrypted).unwrap(), "oidc-top-secret");
    }

    #[test]
    fn test_encrypt_optional_oidc_secret_none_when_empty() {
        let config = Config::from_env().unwrap();
        let result = encrypt_optional_oidc_secret(Some(""), &config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_encrypt_optional_oidc_secret_none_when_whitespace() {
        let config = Config::from_env().unwrap();
        let result = encrypt_optional_oidc_secret(Some("   "), &config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_encrypt_optional_oidc_secret_none_input() {
        let config = Config::from_env().unwrap();
        let result = encrypt_optional_oidc_secret(None, &config).unwrap();
        assert!(result.is_none());
    }

    // ── SAML sanitize_value tests ────────────────────────────────

    #[test]
    fn test_sanitize_saml_value_rejects_xml_special_chars() {
        assert!(sanitize_saml_value("<malicious>").is_empty());
        assert!(sanitize_saml_value("foo>bar").is_empty());
        assert!(sanitize_saml_value("foo&bar").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_rejects_control_chars() {
        assert!(sanitize_saml_value("foo\x00bar").is_empty());
        assert!(sanitize_saml_value("foo\x01bar").is_empty());
        assert!(sanitize_saml_value("foo\x1Fbar").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_allows_whitespace() {
        assert!(!sanitize_saml_value("tab\there").is_empty());
        assert!(!sanitize_saml_value("newline\nhere").is_empty());
        assert!(!sanitize_saml_value("cr\rhere").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_rejects_over_256_chars() {
        let long = "a".repeat(257);
        assert!(sanitize_saml_value(&long).is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_accepts_valid_input() {
        let valid = sanitize_saml_value("alice@example.com");
        assert_eq!(valid, "alice@example.com");
    }

    #[test]
    fn test_sanitize_saml_value_rejects_empty() {
        assert!(sanitize_saml_value("").is_empty());
        assert!(sanitize_saml_value("  ").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_trims_whitespace() {
        let valid = sanitize_saml_value("  user@example.com  ");
        assert_eq!(valid, "user@example.com");
    }

    #[test]
    fn test_sanitize_saml_value_rejects_256_chars_boundary() {
        // 256 chars should be accepted (boundary)
        let valid_256 = "a".repeat(256);
        assert_eq!(sanitize_saml_value(&valid_256).len(), 256);
    }

    // ── SAML XML structure tests ──────────────────────────────────

    /// Build a valid SAML AuthnRequest XML string matching the format
    /// produced by `initiate_saml_login`.
    fn make_saml_authn_request(
        request_id: &str,
        entity_id: &str,
        acs_url: &str,
        destination: &str,
    ) -> String {
        let issue_instant = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{}</saml:Issuer></samlp:AuthnRequest>"#,
            xml_escape(request_id),
            xml_escape(&issue_instant),
            xml_escape(destination),
            xml_escape(acs_url),
            xml_escape(entity_id),
        )
    }

    /// Build a valid SAML Response XML string with the given components.
    fn make_saml_response(
        status_code: &str,
        issuer: &str,
        audience: &str,
        not_on_or_after: Option<&str>,
        name_id: &str,
        attributes: &[(&str, &str)],
    ) -> String {
        let not_on_or_after_attr = match not_on_or_after {
            Some(val) => format!(" NotOnOrAfter=\"{}\"", xml_escape(val)),
            None => String::new(),
        };

        let attr_statements: String = attributes.iter().map(|(name, value)| {
            format!(
                r#"<saml:Attribute Name="{}"><saml:AttributeValue>{}</saml:AttributeValue></saml:Attribute>"#,
                // quick-xml 0.41: escape() takes impl Into<Cow<str>>; deref the
                // &&str tuple fields (0.36's &str parameter auto-derefed them).
                xml_escape(*name),
                xml_escape(*value),
            )
        }).collect();

        let attr_section = if attr_statements.is_empty() {
            String::new()
        } else {
            format!(
                "<saml:AttributeStatement>{}</saml:AttributeStatement>",
                attr_statements
            )
        };

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response123" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>{}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="{}"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion1" IssueInstant="2025-01-01T00:00:01Z">
    <saml:Issuer>{}</saml:Issuer>
    <saml:Subject>
      <saml:NameID>{}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2025-01-02T00:00:00Z" Recipient="https://apexmail.com/api/sso/saml/callback"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions{}>
      <saml:AudienceRestriction>
        <saml:Audience>{}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    {}
  </saml:Assertion>
</samlp:Response>"#,
            xml_escape(issuer),
            xml_escape(status_code),
            xml_escape(issuer),
            xml_escape(name_id),
            not_on_or_after_attr,
            xml_escape(audience),
            attr_section,
        )
    }

    /// Strip the namespace prefix from a qualified XML element name.
    /// Returns the local part (e.g., `samlp:StatusCode` → `StatusCode`).
    fn local_name(full_name: &str) -> &str {
        full_name.rsplit(':').next().unwrap_or(full_name)
    }

    /// Parse a SAML XML string and extract key fields (mirrors the production
    /// logic in `parse_and_validate_saml_response` for testability).
    ///
    /// Uses `local_name()` to handle both namespaced (e.g., `samlp:StatusCode`)
    /// and un-prefixed element names uniformly.
    fn parse_saml_response_xml(xml: &str) -> Result<ParsedSamlFields, String> {
        let mut reader = Reader::from_str(xml);
        let mut in_status_code = false;
        let mut in_issuer = false;
        let mut in_audience = false;
        let mut in_conditions = false;
        let mut in_audience_restriction = false;
        let mut in_name_id = false;
        let mut in_attribute = false;
        let mut in_attribute_value = false;
        let mut current_attr_name: Option<String> = None;

        let mut status_code_value: Option<String> = None;
        let mut issuer_values: Vec<String> = Vec::new();
        let mut audience_value: Option<String> = None;
        let mut not_on_or_after: Option<String> = None;
        let mut name_id_value: Option<String> = None;
        let mut attributes: Vec<(String, String)> = Vec::new();
        let mut text_buf = String::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    text_buf.clear();
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = local_name(&name).to_string();
                    match tag.as_str() {
                        "StatusCode" => in_status_code = true,
                        "Issuer" => in_issuer = true,
                        "Audience" => in_audience = in_conditions && in_audience_restriction,
                        "AudienceRestriction" => in_audience_restriction = true,
                        "Conditions" => {
                            in_conditions = true;
                            // Extract NotOnOrAfter attribute from Conditions element
                            if let Some(attr) = e
                                .attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"NotOnOrAfter")
                            {
                                if let Ok(val) = String::from_utf8(attr.value.to_vec()) {
                                    not_on_or_after = Some(val);
                                }
                            }
                        }
                        "NameID" => in_name_id = true,
                        "Attribute" => {
                            in_attribute = true;
                            current_attr_name = e
                                .attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"Name")
                                .and_then(|a| String::from_utf8(a.value.to_vec()).ok());
                        }
                        "AttributeValue" => in_attribute_value = in_attribute,
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = local_name(&name).to_string();
                    match tag.as_str() {
                        "StatusCode" => in_status_code = false,
                        "Issuer" => in_issuer = false,
                        "Audience" => in_audience = false,
                        "AudienceRestriction" => in_audience_restriction = false,
                        "Conditions" => in_conditions = false,
                        "NameID" => in_name_id = false,
                        "Attribute" => {
                            in_attribute = false;
                            current_attr_name = None;
                        }
                        "AttributeValue" => {
                            if in_attribute_value && in_attribute {
                                if let Some(attr_name) = current_attr_name.take() {
                                    attributes.push((attr_name, text_buf.clone()));
                                    text_buf.clear();
                                }
                            }
                            in_attribute_value = false;
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if let Ok(text) = e.decode() {
                        let text_str = text.as_ref();
                        if in_status_code {
                            status_code_value = Some(text_str.to_string());
                        } else if in_issuer {
                            issuer_values.push(text_str.to_string());
                        } else if in_audience && in_conditions && in_audience_restriction {
                            audience_value = Some(text_str.to_string());
                        } else if in_name_id {
                            name_id_value = Some(text_str.to_string());
                        } else if in_attribute && in_attribute_value {
                            text_buf.push_str(text_str);
                        }
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = local_name(&name).to_string();
                    if tag == "StatusCode" {
                        if let Some(attr) = e
                            .attributes()
                            .filter_map(|a| a.ok())
                            .find(|a| a.key.as_ref() == b"Value")
                        {
                            if let Ok(val) = String::from_utf8(attr.value.to_vec()) {
                                status_code_value = Some(val);
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("SAML XML parse error: {e}")),
                _ => {}
            }
        }

        Ok(ParsedSamlFields {
            status_code: status_code_value.unwrap_or_default(),
            issuer: issuer_values.first().cloned().unwrap_or_default(),
            audience: audience_value.unwrap_or_default(),
            not_on_or_after,
            name_id: name_id_value.unwrap_or_default(),
            attributes,
        })
    }

    /// Helper struct for SAML XML parse result.
    struct ParsedSamlFields {
        status_code: String,
        issuer: String,
        audience: String,
        not_on_or_after: Option<String>,
        name_id: String,
        attributes: Vec<(String, String)>,
    }

    #[test]
    fn test_saml_authn_request_xml_structure() {
        // Verify that the SAML AuthnRequest XML contains required elements:
        // Issuer, protocol namespace, and the ID attribute.
        let entity_id = "urn:apexmail:enterprise";
        let acs_url = "https://apexmail.com/api/sso/saml/callback";
        let destination = "https://idp.example.com/sso";
        let request_id = "_saml_test-uuid";

        let xml = make_saml_authn_request(request_id, entity_id, acs_url, destination);

        // Verify the XML contains required elements
        assert!(
            xml.contains("samlp:AuthnRequest"),
            "Should contain AuthnRequest element"
        );
        assert!(
            xml.contains(&format!("ID=\"{}\"", xml_escape(request_id))),
            "Should contain request ID"
        );
        assert!(
            xml.contains(&format!(
                "AssertionConsumerServiceURL=\"{}\"",
                xml_escape(acs_url)
            )),
            "Should contain ACS URL"
        );
        assert!(
            xml.contains(&format!(
                "<saml:Issuer>{}</saml:Issuer>",
                xml_escape(entity_id)
            )),
            "Should contain Issuer"
        );
        assert!(
            xml.contains("urn:oasis:names:tc:SAML:2.0:protocol"),
            "Should contain SAML protocol namespace"
        );
    }

    #[test]
    fn test_saml_authn_request_xml_parses_correctly() {
        // Verify the AuthnRequest XML can be parsed back with quick_xml,
        // using `local_name()` to handle namespace-prefixed element names.
        let entity_id = "urn:apexmail:enterprise";
        let acs_url = "https://apexmail.com/api/sso/saml/callback";
        let destination = "https://idp.example.com/sso";
        let request_id = "_saml_test-abc123";
        let xml = make_saml_authn_request(request_id, entity_id, acs_url, destination);

        let mut reader = Reader::from_str(&xml);
        let mut found_issuer = false;
        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = local_name(&name);
                    if tag == "Issuer" {
                        found_issuer = true;
                    }
                    if tag == "AuthnRequest" {
                        // Verify the ID attribute is present
                        let has_id = e
                            .attributes()
                            .filter_map(|a| a.ok())
                            .any(|a| a.key.as_ref() == b"ID");
                        assert!(has_id, "AuthnRequest must have ID attribute");
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if found_issuer {
                        assert_eq!(e.decode().unwrap().as_ref(), entity_id);
                        found_issuer = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => panic!("XML parse error: {e}"),
                _ => {}
            }
        }
    }

    #[test]
    fn test_saml_valid_response_parses_status_code_and_issuer() {
        // Verify that a valid SAML response XML correctly extracts StatusCode
        // and Issuer values via quick_xml parsing.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[("email", "user@example.com"), ("role", "admin")],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse valid SAML response");

        assert!(
            parsed.status_code.contains(":Success")
                || parsed.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success",
            "Status code should indicate success, got: {}",
            parsed.status_code
        );
        assert_eq!(parsed.issuer, "urn:apexmail:enterprise");
    }

    #[test]
    fn test_saml_valid_response_parses_audience_restriction() {
        // Verify that the Audience element is correctly extracted from
        // AudienceRestriction.
        let expected_audience = "https://apexmail.com/api/sso/saml/callback";
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            expected_audience,
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse valid SAML response");
        assert_eq!(parsed.audience, expected_audience);
    }

    #[test]
    fn test_saml_ignores_audience_outside_audience_restriction() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion>
        <saml:Audience>https://evil.example/callback</saml:Audience>
        <saml:Conditions>
            <saml:AudienceRestriction>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
    </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML");

        assert!(parsed.audience.is_empty());
    }

    #[test]
    fn test_saml_valid_response_parses_name_id() {
        // Verify that the NameID element is correctly extracted.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "alice@company.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse valid SAML response");
        assert_eq!(parsed.name_id, "alice@company.com");
    }

    #[test]
    fn test_saml_valid_response_parses_attributes() {
        // Verify that Attribute/AttributeValue elements are correctly extracted.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[
                ("email", "user@example.com"),
                ("firstName", "Alice"),
                ("lastName", "Smith"),
            ],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse valid SAML response");
        assert_eq!(parsed.attributes.len(), 3, "Should extract 3 attributes");

        let email_attr = parsed.attributes.iter().find(|(n, _)| n == "email");
        assert!(email_attr.is_some(), "Should have email attribute");
        assert_eq!(email_attr.unwrap().1, "user@example.com");

        let first_name = parsed.attributes.iter().find(|(n, _)| n == "firstName");
        assert!(first_name.is_some(), "Should have firstName attribute");
        assert_eq!(first_name.unwrap().1, "Alice");
    }

    #[test]
    fn test_saml_ignores_attribute_value_outside_attribute() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion>
        <saml:Conditions>
            <saml:AudienceRestriction>
                <saml:Audience>https://apexmail.com/api/sso/saml/callback</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML");

        assert!(parsed.attributes.is_empty());
    }

    #[test]
    fn test_saml_rejects_failure_status_code() {
        // Verify that a SAML response with a non-success StatusCode is
        // detected as failed. The production code returns an error when the
        // status code is not `:Success`.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse XML");
        let is_not_success = !parsed.status_code.ends_with(":Success")
            && parsed.status_code != "urn:oasis:names:tc:SAML:2.0:status:Success";
        assert!(
            is_not_success,
            "Status code '{}' should be detected as failure",
            parsed.status_code
        );
    }

    #[test]
    fn test_saml_rejects_denied_status_code() {
        // Verify that a SAML response with AuthnFailed status is detected.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse XML");
        let is_not_success = !parsed.status_code.ends_with(":Success")
            && parsed.status_code != "urn:oasis:names:tc:SAML:2.0:status:Success";
        assert!(is_not_success, "AuthnFailed should be detected as failure");
    }

    #[test]
    fn test_saml_issuer_mismatch_detection() {
        // Verify issuer mismatch is detectable. The production code compares
        // the extracted issuer against the configured entity_id.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:evil:entity", // Different from expected "urn:apexmail:enterprise"
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse XML");
        assert_eq!(parsed.issuer, "urn:evil:entity");
        // The production code would compare: parsed.issuer == expected_entity_id
        assert_ne!(
            parsed.issuer, "urn:apexmail:enterprise",
            "Issuer mismatch should be detectable"
        );
    }

    #[test]
    fn test_saml_audience_mismatch_detection() {
        // Verify audience mismatch is detectable. The production code compares
        // the extracted audience against the configured ACS URL.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://evil.com/callback", // Different from expected ACS URL
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse XML");
        assert_eq!(parsed.audience, "https://evil.com/callback");
        assert_ne!(
            parsed.audience, "https://apexmail.com/api/sso/saml/callback",
            "Audience mismatch should be detectable"
        );
    }

    #[test]
    fn test_saml_detects_missing_audience_restriction() {
        // Verify that XML without AudienceRestriction is handled.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML without audience");
        assert!(
            parsed.audience.is_empty(),
            "Audience should be empty when not present"
        );
    }

    #[test]
    fn test_saml_detects_missing_issuer() {
        // Verify that XML without Issuer is handled.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML without issuer");
        assert!(
            parsed.issuer.is_empty(),
            "Issuer should be empty when not present"
        );
    }

    #[test]
    fn test_saml_detects_missing_name_id() {
        // Verify that XML without NameID is handled.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML without NameID");
        assert!(
            parsed.name_id.is_empty(),
            "NameID should be empty when not present"
        );
    }

    #[test]
    fn test_saml_not_on_or_after_expiry_detection() {
        // Verify that a NotOnOrAfter date in the past is detectable as expired.
        let past_date = "2020-01-01T00:00:00Z";
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some(past_date),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse SAML response");

        // Verify the NotOnOrAfter value was extracted
        assert_eq!(parsed.not_on_or_after, Some(past_date.to_string()));

        // Verify it's in the past (would be rejected by prod code)
        if let Some(ref expiry) = parsed.not_on_or_after {
            let parsed_date = chrono::DateTime::parse_from_rfc3339(expiry)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
            if let Some(expiry_time) = parsed_date {
                assert!(
                    Utc::now() > expiry_time,
                    "Expired assertion should be detected: {expiry} is in the past"
                );
            }
        }
    }

    #[test]
    fn test_saml_not_on_or_after_future_date_accepted() {
        // Verify that a NotOnOrAfter date in the future is NOT detected as expired.
        let future_date = "2030-12-01T00:00:00Z";
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some(future_date),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse SAML response");
        assert_eq!(parsed.not_on_or_after, Some(future_date.to_string()));

        if let Some(ref expiry) = parsed.not_on_or_after {
            let parsed_date = chrono::DateTime::parse_from_rfc3339(expiry)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
            if let Some(expiry_time) = parsed_date {
                assert!(
                    Utc::now() < expiry_time,
                    "Future assertion should NOT be expired"
                );
            }
        }
    }

    #[test]
    fn test_saml_not_on_or_after_alternate_format() {
        // Verify parsing of NotOnOrAfter in `%Y-%m-%dT%H:%M:%S%:z` format
        // (the fallback format in production code).
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_a1" IssueInstant="2025-01-01T00:00:01Z">
    <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotOnOrAfter="2030-06-15T12:30:00+00:00">
      <saml:AudienceRestriction>
        <saml:Audience>https://apexmail.com/api/sso/saml/callback</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse SAML response");
        assert!(
            parsed.not_on_or_after.is_some(),
            "NotOnOrAfter should be extracted from SAML response"
        );
    }

    #[test]
    fn test_saml_no_not_on_or_after_condition() {
        // Verify that SAML XML without a NotOnOrAfter attribute is handled.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            None, // No NotOnOrAfter
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse SAML response");
        assert!(
            parsed.not_on_or_after.is_none(),
            "NotOnOrAfter should be None when not present"
        );
    }

    #[test]
    fn test_saml_status_code_via_empty_element() {
        // Verify that StatusCode can be parsed from a self-closing element
        // (the `Empty` event path in the production parser).
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions>
      <saml:AudienceRestriction>
        <saml:Audience>https://apexmail.com/api/sso/saml/callback</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse SAML response");
        assert_eq!(
            parsed.status_code, "urn:oasis:names:tc:SAML:2.0:status:Success",
            "Should parse StatusCode from self-closing element"
        );
    }

    #[test]
    fn test_saml_malformed_xml_handled_gracefully() {
        // Verify that malformed XML does not panic; quick_xml is a streaming
        // parser and does not validate well-formedness, so it returns Ok with
        // default/empty fields rather than an error.
        let malformed = "<samlp:Response><unclosed>";
        let result = parse_saml_response_xml(malformed);
        // quick_xml streaming parser does not error on unclosed tags
        assert!(
            result.is_ok(),
            "Malformed XML should not cause parse error in streaming parser"
        );
        let parsed = result.unwrap();
        assert!(parsed.status_code.is_empty());
        assert!(parsed.issuer.is_empty());
    }

    #[test]
    fn test_saml_empty_xml_handled_gracefully() {
        // Verify that empty XML does not panic. quick_xml returns Eof
        // immediately, so the parser returns Ok with default values.
        let result = parse_saml_response_xml("");
        assert!(result.is_ok(), "Empty XML should not cause parse error");
        let parsed = result.unwrap();
        assert!(parsed.status_code.is_empty());
        assert!(parsed.issuer.is_empty());
    }

    // ── OIDC flow tests ───────────────────────────────────────────

    #[test]
    fn test_oidc_state_generation_uniqueness() {
        // Verify that generate_random_token produces unique states (used for
        // OIDC `state` parameter).
        let state1 = generate_random_token(32);
        let state2 = generate_random_token(32);
        assert_ne!(state1, state2, "OIDC states must be unique");
    }

    #[test]
    fn test_oidc_state_is_hex() {
        // Verify OIDC state is valid hex (derived from generate_random_token).
        let state = generate_random_token(16);
        assert_eq!(state.len(), 32);
        assert!(state.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_oidc_redirect_url_contains_required_params() {
        // Verify the OIDC redirect URL format contains all required OAuth2
        // authorization parameters. This mirrors the format in
        // `initiate_oidc_login`.
        let issuer = "https://accounts.google.com";
        let client_id = "test-client-id-123";
        let redirect_uri = "https://apexmail.com/api/sso/oidc/callback";
        let scopes = "openid profile email";
        let state = generate_random_token(32);
        let code_verifier = generate_pkce_verifier();
        let code_challenge = generate_pkce_challenge(&code_verifier);

        let redirect_url = format!(
            "{}/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            issuer,
            urlencoding::encode(client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(scopes),
            urlencoding::encode(&state),
            urlencoding::encode(&code_challenge),
        );

        assert!(redirect_url.starts_with("https://accounts.google.com/authorize?"));
        assert!(redirect_url.contains("response_type=code"));
        assert!(redirect_url.contains("code_challenge_method=S256"));
        assert!(redirect_url.contains(&format!("state={}", urlencoding::encode(&state))));
        assert!(redirect_url.contains(&format!(
            "code_challenge={}",
            urlencoding::encode(&code_challenge)
        )));
    }

    #[test]
    fn test_oidc_redirect_url_contains_client_id() {
        // Verify the redirect URL includes the client_id parameter.
        let redirect_url = format!(
            "{}/authorize?client_id={}",
            "https://idp.example.com",
            urlencoding::encode("my-client-id")
        );
        assert!(redirect_url.contains("client_id=my-client-id"));
    }

    // ── Session / token tests ─────────────────────────────────────

    #[test]
    fn test_session_token_is_hex() {
        // Verify session tokens (from generate_random_token) are valid hex.
        let token = generate_random_token(64);
        assert_eq!(token.len(), 128);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_session_token_uniqueness() {
        // Verify two session tokens are unique.
        let t1 = generate_random_token(64);
        let t2 = generate_random_token(64);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_configure_request_with_all_optional_fields() {
        // Verify SSOConfigureRequest serde with all fields populated.
        let req = SSOConfigureRequest {
            tenant_id: "tenant_123".into(),
            provider_type: "oidc".into(),
            domain: "company.com".into(),
            enabled: Some(true),
            idp_entity_id: Some("urn:company".into()),
            sso_url: Some("https://company.okta.com/sso".into()),
            certificate: Some("MIID....".into()),
            oidc_client_id: Some("client_123".into()),
            oidc_client_secret: Some("secret".into()),
            oidc_issuer: Some("https://company.okta.com".into()),
            attribute_mapping: Some(serde_json::json!({"email": "email"})),
            enforce_sso: Some(true),
            session_duration_hours: Some(24),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("oidc"));
        assert!(json.contains("attribute_mapping"));
        let parsed: SSOConfigureRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_duration_hours, Some(24));
    }

    // ── SAML sanitize_value edge case tests ───────────────────────

    #[test]
    fn test_sanitize_saml_value_rejects_only_control_chars() {
        // Verify values consisting only of control characters are rejected.
        assert!(sanitize_saml_value("\x00\x01\x02").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_accepts_email_like() {
        // Verify common email-like values pass validation.
        assert_eq!(
            sanitize_saml_value("alice@example.com"),
            "alice@example.com"
        );
        assert_eq!(
            sanitize_saml_value("bob+tag@example.co.uk"),
            "bob+tag@example.co.uk"
        );
        assert_eq!(
            sanitize_saml_value("user@sub.example.org"),
            "user@sub.example.org"
        );
    }

    #[test]
    fn test_sanitize_saml_value_rejects_combined_xml_and_control() {
        // Verify values with combined XML special chars and control chars are rejected.
        assert!(sanitize_saml_value("<script\x00>").is_empty());
        assert!(sanitize_saml_value("foo&\x01bar").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_rejects_leading_trailing_whitespace_only() {
        // Verify whitespace-only values become empty after trim.
        assert!(sanitize_saml_value("   ").is_empty());
        assert!(sanitize_saml_value("\t\n\r").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_exact_256_boundary() {
        // Verify the exact 256-char boundary passes.
        let exact = "a".repeat(256);
        assert_eq!(sanitize_saml_value(&exact).len(), 256);
    }

    #[test]
    fn test_sanitize_saml_value_257_rejected() {
        // Verify that 257 chars are rejected.
        let too_long = "a".repeat(257);
        assert!(sanitize_saml_value(&too_long).is_empty());
    }
    // ═══════════════════════════════════════════════════════════════════
    // Signed-SAML fixture machinery
    //
    // An in-test IdP: a real RSA keypair (see tests/keys/) plus a minimal
    // big-integer RSA implementation so tests can produce genuinely signed
    // XML-DSig envelopes (RSA-SHA256, exclusive C14N over SignedInfo,
    // enveloped-signature transform over the whole document). Every byte of
    // the signature path is exercised through the production verifier, so a
    // signing bug fails loudly instead of faking coverage.
    // ═══════════════════════════════════════════════════════════════════

    pub(crate) mod idp {
        use super::*;

        // ── big integer (little-endian u64 limbs) ──

        pub fn mul(a: &[u64], b: &[u64]) -> Vec<u64> {
            let mut out = vec![0u64; a.len() + b.len()];
            for (i, &ai) in a.iter().enumerate() {
                let mut carry: u128 = 0;
                for (j, &bj) in b.iter().enumerate() {
                    let t = ai as u128 * bj as u128 + out[i + j] as u128 + carry;
                    out[i + j] = t as u64;
                    carry = t >> 64;
                }
                let mut k = i + b.len();
                while carry > 0 {
                    let t = out[k] as u128 + carry;
                    out[k] = t as u64;
                    carry = t >> 64;
                    k += 1;
                }
            }
            while out.len() > 1 && *out.last().unwrap() == 0 {
                out.pop();
            }
            out
        }

        pub fn cmp(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
            let n = a.len().max(b.len());
            for i in (0..n).rev() {
                let av = a.get(i).copied().unwrap_or(0);
                let bv = b.get(i).copied().unwrap_or(0);
                if av != bv {
                    return av.cmp(&bv);
                }
            }
            std::cmp::Ordering::Equal
        }

        fn shl(a: &[u64], shift: u32) -> Vec<u64> {
            if shift == 0 {
                return a.to_vec();
            }
            let mut out = vec![0u64; a.len()];
            for i in 0..a.len() {
                if i > 0 {
                    out[i] |= a[i - 1] >> (64 - shift);
                }
                out[i] |= a[i] << shift;
            }
            out
        }

        fn shr(a: &[u64], shift: u32) -> Vec<u64> {
            if shift == 0 {
                return a.to_vec();
            }
            let mut out = vec![0u64; a.len()];
            for i in 0..a.len() {
                out[i] = a[i] >> shift;
                if i + 1 < a.len() {
                    out[i] |= a[i + 1] << (64 - shift);
                }
            }
            while out.len() > 1 && *out.last().unwrap() == 0 {
                out.pop();
            }
            out
        }

        /// Knuth algorithm D: `(quotient, remainder)` of `u / v`.
        pub fn divmod(u: &[u64], v: &[u64]) -> (Vec<u64>, Vec<u64>) {
            assert!(!v.is_empty() && *v.last().unwrap() != 0, "zero divisor");
            if cmp(u, v) == std::cmp::Ordering::Less {
                return (vec![0], u.to_vec());
            }
            if v.len() == 1 {
                let d = v[0];
                let mut q = vec![0u64; u.len()];
                let mut rem: u128 = 0;
                for i in (0..u.len()).rev() {
                    let cur = (rem << 64) | u[i] as u128;
                    q[i] = (cur / d as u128) as u64;
                    rem = cur % d as u128;
                }
                while q.len() > 1 && *q.last().unwrap() == 0 {
                    q.pop();
                }
                return (q, vec![rem as u64]);
            }
            let shift = v[v.len() - 1].leading_zeros();
            let vn = shl(v, shift);
            let mut padded = u.to_vec();
            padded.push(0);
            let mut un = shl(&padded, shift);
            while un.len() < padded.len() {
                un.push(0);
            }
            let n = vn.len();
            let m = un.len() - n - 1;
            let mut q = vec![0u64; m + 1];
            let vtop = vn[n - 1];
            let vnext = vn[n - 2];
            for j in (0..=m).rev() {
                let num = ((un[j + n] as u128) << 64) | un[j + n - 1] as u128;
                let mut qhat = num / vtop as u128;
                let mut rhat = num % vtop as u128;
                while qhat >> 64 != 0
                    || qhat * vnext as u128 > ((rhat << 64) | un[j + n - 2] as u128)
                {
                    qhat -= 1;
                    rhat += vtop as u128;
                    if rhat >> 64 != 0 {
                        break;
                    }
                }
                let mut borrow: u64 = 0;
                let mut carry: u64 = 0;
                for i in 0..n {
                    let p = qhat * vn[i] as u128 + carry as u128;
                    carry = (p >> 64) as u64;
                    let (r1, b1) = un[i + j].overflowing_sub(p as u64);
                    let (r2, b2) = r1.overflowing_sub(borrow);
                    un[i + j] = r2;
                    borrow = (b1 as u64) + (b2 as u64);
                }
                let (r1, b1) = un[j + n].overflowing_sub(carry);
                let (r2, b2) = r1.overflowing_sub(borrow);
                un[j + n] = r2;
                if b1 || b2 {
                    qhat -= 1;
                    let mut carry: u128 = 0;
                    for i in 0..n {
                        let t = un[i + j] as u128 + vn[i] as u128 + carry;
                        un[i + j] = t as u64;
                        carry = t >> 64;
                    }
                    un[j + n] = un[j + n].wrapping_add(carry as u64);
                }
                q[j] = qhat as u64;
            }
            while q.len() > 1 && *q.last().unwrap() == 0 {
                q.pop();
            }
            let mut rem = un[..n].to_vec();
            rem = shr(&rem, shift);
            (q, rem)
        }

        pub fn modexp(base: &[u64], exp: &[u64], modulus: &[u64]) -> Vec<u64> {
            let reduced = divmod(base, modulus).1;
            let mut result = vec![1u64];
            for i in (0..exp.len()).rev() {
                for bit in (0..64).rev() {
                    result = divmod(&mul(&result, &result), modulus).1;
                    if (exp[i] >> bit) & 1 == 1 {
                        result = divmod(&mul(&result, &reduced), modulus).1;
                    }
                }
            }
            result
        }

        fn le_bytes_to_limbs(bytes: &[u8]) -> Vec<u64> {
            let mut out = vec![0u64; bytes.len().div_ceil(8)];
            for (i, &b) in bytes.iter().rev().enumerate() {
                out[i / 8] |= (b as u64) << ((i % 8) * 8);
            }
            out
        }

        fn limbs_to_be_bytes(limbs: &[u64], len: usize) -> Vec<u8> {
            let mut out = vec![0u8; len];
            for (i, limb) in limbs.iter().enumerate() {
                for b in 0..8 {
                    let idx = match len.checked_sub(1 + i * 8 + b) {
                        Some(idx) => idx,
                        None => break,
                    };
                    out[idx] = (limb >> (8 * b)) as u8;
                }
            }
            out
        }

        // ── DER (PKCS#8) private-key parse ──

        fn read_tlv(buf: &[u8], pos: usize) -> (u8, &[u8], usize) {
            let tag = buf[pos];
            let mut p = pos + 1;
            let first = buf[p];
            p += 1;
            let len = if first & 0x80 == 0 {
                first as usize
            } else {
                let count = (first & 0x7f) as usize;
                let mut len = 0usize;
                for _ in 0..count {
                    len = (len << 8) | buf[p] as usize;
                    p += 1;
                }
                len
            };
            (tag, &buf[p..p + len], p + len)
        }

        /// An RSA private key with just the pieces signing needs.
        pub struct RsaPrivateKey {
            pub n: Vec<u64>,
            pub e: Vec<u64>,
            pub d: Vec<u64>,
            pub byte_len: usize,
        }

        impl RsaPrivateKey {
            pub fn from_pkcs8_pem(pem: &str) -> RsaPrivateKey {
                use base64::Engine;
                let body: String = pem
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .map(|line| line.trim())
                    .collect();
                let der = base64::engine::general_purpose::STANDARD
                    .decode(body.as_bytes())
                    .expect("PKCS#8 base64");
                // PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey }
                let (tag, info, _) = read_tlv(&der, 0);
                assert_eq!(tag, 0x30);
                let (_t_version, _v, after_version) = read_tlv(info, 0);
                let (_t_alg, _alg, after_alg) = read_tlv(info, after_version);
                let (t_octet, pkcs1, _) = read_tlv(info, after_alg);
                assert_eq!(t_octet, 0x04, "expected OCTET STRING privateKey");
                // RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, ... }
                let (t_seq, seq, _) = read_tlv(pkcs1, 0);
                assert_eq!(t_seq, 0x30);
                let (_tv, _version, p) = read_tlv(seq, 0);
                let (_tn, n, p) = read_tlv(seq, p);
                let (_te, e, p) = read_tlv(seq, p);
                let (_td, d, _p) = read_tlv(seq, p);
                let n = if n[0] == 0 { &n[1..] } else { n };
                let d = if d[0] == 0 { &d[1..] } else { d };
                let byte_len = n.len();
                RsaPrivateKey {
                    n: le_bytes_to_limbs(n),
                    e: le_bytes_to_limbs(e),
                    d: le_bytes_to_limbs(d),
                    byte_len,
                }
            }

            /// The public modulus, big-endian, without a leading zero byte —
            /// the exact byte string an RSA JWK's `n` field carries.
            pub fn modulus_be(&self) -> Vec<u8> {
                limbs_to_be_bytes(&self.n, self.byte_len)
            }

            /// The public exponent, big-endian, minimal length (the JWK `e`).
            pub fn exponent_be(&self) -> Vec<u8> {
                let raw = limbs_to_be_bytes(&self.e, self.byte_len);
                let first = raw
                    .iter()
                    .position(|&byte| byte != 0)
                    .unwrap_or(raw.len() - 1);
                raw[first..].to_vec()
            }

            /// RSASSA-PKCS1-v1_5 signature over `message` with SHA-256.
            pub fn sign_pkcs1_sha256(&self, message: &[u8]) -> Vec<u8> {
                let digest = Sha256::digest(message);
                // DigestInfo for SHA-256 (RFC 8017 §9.2 note 1).
                let t: Vec<u8> = [
                    &[
                        0x30u8, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                    ][..],
                    &digest,
                ]
                .concat();
                let k = self.byte_len;
                let mut em = vec![0u8, 0x01];
                em.extend(std::iter::repeat_n(0xff, k - 3 - t.len()));
                em.push(0x00);
                em.extend_from_slice(&t);
                assert_eq!(em.len(), k);
                let sig = modexp(&le_bytes_to_limbs(&em), &self.d, &self.n);
                limbs_to_be_bytes(&sig, k)
            }
        }

        // ── XML-DSig envelope assembly ──

        use xml_sec::c14n::{canonicalize_xml, C14nAlgorithm, C14nMode};

        const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
        const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
        const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
        const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

        fn b64(data: &[u8]) -> String {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(data)
        }

        /// Sign `document_prefix` + `document_suffix` (the SAML response with
        /// the Signature element excised) and return the full document with
        /// the enveloped `<ds:Signature>` spliced between them.
        pub fn seal(document_prefix: &str, document_suffix: &str, key: &RsaPrivateKey) -> String {
            // Digest over the canonicalised unsigned document: exactly what
            // the verifier's enveloped-signature transform leaves behind.
            let unsigned = format!("{document_prefix}{document_suffix}");
            let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            let canonical = canonicalize_xml(unsigned.as_bytes(), &algorithm)
                .expect("canonicalize unsigned SAML document");
            let digest = Sha256::digest(&canonical);

            let signed_info = format!(
                r#"<ds:SignedInfo xmlns:ds="{DS_NS}"><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
                b64(&digest)
            );
            // The verifier canonicalises the SignedInfo SUBTREE with its
            // declared exclusive C14N — canonicalising the same bytes
            // standalone produces the identical octets.
            let exc = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
            let canonical_signed_info =
                canonicalize_xml(signed_info.as_bytes(), &exc).expect("canonicalize SignedInfo");
            let signature = key.sign_pkcs1_sha256(&canonical_signed_info);

            format!(
                "{document_prefix}<ds:Signature xmlns:ds=\"{DS_NS}\">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>{document_suffix}",
                b64(&signature)
            )
        }

        /// Sign a JOSE JWT with RS256 — the same RSASSA-PKCS1-v1_5/SHA-256
        /// primitive `seal` uses for XML-DSig, applied to the base64url
        /// signing input. Exercises the production JWKS verification path in
        /// `validate_oidc_id_token` end-to-end.
        pub fn sign_rs256_jwt(
            kid: &str,
            claims: &serde_json::Value,
            key: &RsaPrivateKey,
        ) -> String {
            use base64::Engine;
            let b64url =
                |data: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
            let header = format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{kid}"}}"#);
            let signing_input = format!(
                "{}.{}",
                b64url(header.as_bytes()),
                b64url(claims.to_string().as_bytes())
            );
            let signature = key.sign_pkcs1_sha256(signing_input.as_bytes());
            format!("{signing_input}.{}", b64url(&signature))
        }

        /// A VALID signature whose ds:Reference targets a SUB-NODE
        /// (`URI="#{target}"`) instead of the whole document (audit P2-7):
        /// the signed-then-sub-node document must be refused by the
        /// signed-node binding even though the signature itself verifies.
        pub fn seal_with_targeted_reference(
            document_prefix: &str,
            document_suffix: &str,
            key: &RsaPrivateKey,
            target: &str,
        ) -> String {
            let unsigned = format!("{document_prefix}{document_suffix}");
            let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            let canonical = canonicalize_xml(unsigned.as_bytes(), &algorithm)
                .expect("canonicalize unsigned SAML document");
            let digest = Sha256::digest(&canonical);

            let signed_info = format!(
                r##"<ds:SignedInfo xmlns:ds="{DS_NS}"><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI="#{target}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
                b64(&digest)
            );
            let exc = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
            let canonical_signed_info =
                canonicalize_xml(signed_info.as_bytes(), &exc).expect("canonicalize SignedInfo");
            let signature = key.sign_pkcs1_sha256(&canonical_signed_info);

            format!(
                "{document_prefix}<ds:Signature xmlns:ds=\"{DS_NS}\">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>{document_suffix}",
                b64(&signature)
            )
        }
    }

    pub(crate) const IDP_PRIVATE_KEY_PEM: &str = include_str!("../tests/keys/saml_idp_key.pem");
    pub(crate) const IDP_CERTIFICATE_PEM: &str = include_str!("../tests/keys/saml_idp_cert.pem");

    /// The properties of one IdP response fixture; every refusal arm of the
    /// parser is a small mutation of this struct.
    pub(crate) struct SamlFixture {
        /// The IdP entity id — BOTH Issuer elements.
        pub issuer: String,
        /// The SP entity id — the Assertion Audience (audit P2-5).
        pub audience: String,
        /// The ACS URL — the Response Destination and the
        /// SubjectConfirmationData Recipient (audit P2-5).
        pub acs_url: String,
        /// The staged AuthnRequest id echoed in InResponseTo (audit P2-6).
        pub in_response_to: Option<String>,
        pub name_id: String,
        pub status_value: String,
        pub assertion_id: String,
        pub not_before: Option<DateTime<Utc>>,
        pub not_on_or_after: Option<DateTime<Utc>>,
        pub attributes: Vec<(String, String)>,
        pub include_signature: bool,
        pub include_audience: bool,
        pub include_conditions: bool,
        pub include_scd: bool,
    }

    impl SamlFixture {
        /// A fully valid response for the deployment context: the Issuers
        /// name the IdP, the Audience names the SP, the Destination and
        /// Recipient are the ACS URL, and InResponseTo names a request the
        /// test stages via [`stage_saml_authn_request`].
        pub(crate) fn valid(idp_entity_id: &str, sp_entity_id: &str, acs_url: &str) -> SamlFixture {
            SamlFixture {
                issuer: idp_entity_id.to_string(),
                audience: sp_entity_id.to_string(),
                acs_url: acs_url.to_string(),
                in_response_to: Some(format!("_saml_{}", Uuid::new_v4())),
                name_id: "alice.smith@example.com".to_string(),
                status_value: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
                assertion_id: format!("_assertion_{}", Uuid::new_v4()),
                not_before: Some(Utc::now() - chrono::Duration::minutes(2)),
                not_on_or_after: Some(Utc::now() + chrono::Duration::minutes(5)),
                attributes: vec![
                    ("email".to_string(), "alice.smith@example.com".to_string()),
                    ("group".to_string(), "engineering".to_string()),
                ],
                include_signature: true,
                include_audience: true,
                include_conditions: true,
                include_scd: true,
            }
        }

        fn subject_confirmation_data(&self) -> String {
            if !self.include_scd {
                return String::new();
            }
            let in_response_to = self
                .in_response_to
                .as_deref()
                .map(|id| format!(" InResponseTo=\"{}\"", xml_escape(id)))
                .unwrap_or_default();
            format!(
                "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
<saml:SubjectConfirmationData Recipient=\"{}\" NotOnOrAfter=\"{}\"{in_response_to}/>\
</saml:SubjectConfirmation>",
                xml_escape(&self.acs_url),
                self.not_on_or_after
                    .unwrap_or_else(|| Utc::now() + chrono::Duration::minutes(5))
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            )
        }

        pub(crate) fn unsigned_document(&self) -> String {
            let conditions = if self.include_conditions {
                let mut attrs = String::new();
                if let Some(nb) = self.not_before {
                    attrs.push_str(&format!(
                        " NotBefore=\"{}\"",
                        nb.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                    ));
                }
                if let Some(e) = self.not_on_or_after {
                    attrs.push_str(&format!(
                        " NotOnOrAfter=\"{}\"",
                        e.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                    ));
                }
                format!("<saml:Conditions{attrs}>")
            } else {
                String::new()
            };
            let conditions_close = if self.include_conditions {
                "</saml:Conditions>"
            } else {
                ""
            };
            let audience = if self.include_audience {
                format!(
                    "<saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction>",
                    xml_escape(&self.audience)
                )
            } else {
                String::new()
            };
            let attributes: String = self
                .attributes
                .iter()
                .map(|(name, value)| {
                    format!(
                        "<saml:Attribute Name=\"{name}\"><saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>"
                    )
                })
                .collect();
            format!(
                "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp_cov\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\" Destination=\"{}\"{}>\
<samlp:Status><samlp:StatusCode Value=\"{status}\"/></samlp:Status>\
<saml:Issuer>{issuer}</saml:Issuer>\
<saml:Assertion ID=\"{assertion}\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\">\
<saml:Issuer>{issuer}</saml:Issuer>\
<saml:Subject><saml:NameID>{name_id}</saml:NameID>{scd}</saml:Subject>\
{conditions}{audience}{conditions_close}<saml:AttributeStatement>{attributes}</saml:AttributeStatement>\
</saml:Assertion>\
</samlp:Response>",
                xml_escape(&self.acs_url),
                self.in_response_to
                    .as_deref()
                    .map(|id| format!(" InResponseTo=\"{}\"", xml_escape(id)))
                    .unwrap_or_default(),
                status = self.status_value,
                issuer = self.issuer,
                assertion = self.assertion_id,
                name_id = self.name_id,
                scd = self.subject_confirmation_data(),
            )
        }

        /// The full signed document (or unsigned when
        /// `include_signature == false`).
        pub(crate) fn render(&self, key: &idp::RsaPrivateKey) -> String {
            let document = self.unsigned_document();
            if !self.include_signature {
                return document;
            }
            // Splice point: right before the closing Response element.
            let split = document
                .rfind("</samlp:Response>")
                .expect("fixture has a Response root");
            let (prefix, suffix) = document.split_at(split);
            idp::seal(prefix, suffix, key)
        }
    }

    // ── pure signing-machinery sanity (openssl-verified construction) ──

    #[test]
    fn idp_key_parses_and_signs_deterministically() {
        let key = idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM);
        assert_eq!(key.byte_len, 256, "the fixture key is RSA-2048");
        let sig = key.sign_pkcs1_sha256(b"apexmail saml fixture");
        assert_eq!(sig.len(), 256);
        assert_eq!(sig, key.sign_pkcs1_sha256(b"apexmail saml fixture"));
        assert_ne!(sig, key.sign_pkcs1_sha256(b"apexmail saml fixture 2"));
    }

    #[test]
    fn bignum_matches_known_small_values() {
        assert_eq!(idp::modexp(&[2], &[10], &[1000]), vec![24]);
        assert_eq!(idp::mul(&[3, 0], &[5]), vec![15]);
        assert_eq!(idp::divmod(&[100], &[7]), (vec![14], vec![2]));
        // A divisor whose top limb has leading zeros forces the normalized
        // (shifted) division path.
        let x = vec![0xdead_beef, 0x1234, 0x5678, 9];
        let y = vec![0xfeed_face, 0x9999, 3];
        let product = idp::mul(&x, &y);
        let (q, r) = idp::divmod(&product, &y);
        assert_eq!(q, x, "quotient");
        assert!(r.iter().all(|&limb| limb == 0), "remainder is zero");
        // A dividend that needs the padded-high-limb normalization shift.
        let u = vec![0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 5];
        let v = vec![0x8000_0000_0000_0001, 1];
        let (q3, r3) = idp::divmod(&u, &v);
        assert!(idp::cmp(&r3, &v) == std::cmp::Ordering::Less);
        let check = idp::mul(&q3, &v);
        assert!(idp::cmp(&check, &u) != std::cmp::Ordering::Greater);
    }

    #[test]
    fn saml_fixture_renders_the_no_conditions_and_attributeless_shapes() {
        let key = IDP_KEY.get_or_init(|| idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM));
        let mut fixture = SamlFixture::valid(
            "https://idp.example.com",
            "https://sp.example.com",
            "https://acs",
        );
        fixture.include_conditions = false;
        let without_conditions = fixture.unsigned_document();
        assert!(!without_conditions.contains("saml:Conditions"));
        let signed = fixture.render(key);
        assert!(signed.contains("<ds:Signature "), "signed envelope present");

        fixture.attributes.clear();
        assert!(!fixture.unsigned_document().contains("saml:Attribute Name"));

        fixture.not_before = None;
        fixture.not_on_or_after = None;
        assert!(!fixture.unsigned_document().contains("NotBefore"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // P2-5 deconflation + P2-7 structural hardening + P2-8 fail-closed
    // expiration: the pure claim-check matrix (signatures are a separate
    // gate; here each ground truth is mutated INDEPENDENTLY and only the
    // correct semantics pass).
    // ═══════════════════════════════════════════════════════════════════

    const DECONFL_IDP: &str = "https://idp.deconfl.example.com/metadata";
    const DECONFL_SP: &str = "https://sp.apexmail.example.com/saml/metadata";
    const DECONFL_ACS: &str = "https://acs.apexmail.example.com/sso/callback";

    fn deconflation_fixture() -> SamlFixture {
        let mut fixture = SamlFixture::valid(DECONFL_IDP, DECONFL_SP, DECONFL_ACS);
        fixture.in_response_to = None;
        fixture
    }

    fn deconflation_ctx() -> SamlValidationContext {
        SamlValidationContext {
            idp_entity_id: DECONFL_IDP.to_string(),
            sp_entity_id: DECONFL_SP.to_string(),
            acs_url: DECONFL_ACS.to_string(),
            expected_request_id: None,
        }
    }

    #[test]
    fn deconflated_claims_only_pass_with_the_correct_semantics() {
        // The one correct assignment of all four ground truths passes.
        let validated = validate_saml_document_claims(
            &deconflation_fixture().unsigned_document(),
            &deconflation_ctx(),
        )
        .expect("correct Destination/Recipient/Audience/Issuer semantics validate");
        assert_eq!(validated.name_id, "alice.smith@example.com");
    }

    #[test]
    fn response_destination_is_checked_against_the_acs_not_the_audience() {
        // Mutate ONLY the Response/Destination: an Audience-shaped value in
        // the Destination must not pass (P2-5 deconflation).
        let mut fixture = deconflation_fixture();
        fixture.acs_url = format!("{DECONFL_SP}/wrong-acs");
        let error =
            validate_saml_document_claims(&fixture.unsigned_document(), &deconflation_ctx())
                .expect_err("a wrong Destination is refused");
        assert!(
            error.contains("Destination does not match"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn scd_recipient_is_checked_against_the_acs_independently() {
        // Mutate ONLY the SubjectConfirmationData/Recipient (the Destination
        // stays correct): P2-5 deconflation treats them as separate truths.
        let document = deconflation_fixture().unsigned_document().replace(
            &format!("Recipient=\"{DECONFL_ACS}\""),
            "Recipient=\"https://evil.example.com/acs\"",
        );
        assert!(document.contains("evil.example.com"));
        let error = validate_saml_document_claims(&document, &deconflation_ctx())
            .expect_err("a wrong Recipient is refused");
        assert!(
            error.contains("Recipient does not match"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn assertion_audience_is_checked_against_the_sp_entity_not_the_acs() {
        // Mutate ONLY the Audience: the ACS URL (the pre-fix conflation) must
        // NOT be accepted as an Audience — the Audience names the SP entity.
        let document = deconflation_fixture().unsigned_document().replace(
            &format!("<saml:Audience>{DECONFL_SP}</saml:Audience>"),
            &format!("<saml:Audience>{DECONFL_ACS}</saml:Audience>"),
        );
        let error = validate_saml_document_claims(&document, &deconflation_ctx())
            .expect_err("an Audience holding the ACS URL is refused");
        assert!(
            error.contains("AudienceRestriction does not match"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn response_and_assertion_issuers_are_checked_independently() {
        // Mutate ONLY the RESPONSE Issuer (assertion Issuer stays correct).
        let response_mutated = deconflation_fixture().unsigned_document().replacen(
            &format!("<saml:Issuer>{DECONFL_IDP}</saml:Issuer>"),
            "<saml:Issuer>https://evil.example.com/metadata</saml:Issuer>",
            1,
        );
        let error = validate_saml_document_claims(&response_mutated, &deconflation_ctx())
            .expect_err("a wrong Response Issuer is refused");
        assert!(
            error.contains("Issuer does not match"),
            "unexpected: {error}"
        );

        // Mutate ONLY the ASSERTION Issuer (response Issuer stays correct).
        let assertion_mutated = deconflation_fixture()
            .unsigned_document()
            .replacen(
                &format!("<saml:Issuer>{DECONFL_IDP}</saml:Issuer>"),
                "<saml:Issuer>https://evil.example.com/metadata</saml:Issuer>",
                2,
            )
            .replacen(
                &"<saml:Issuer>https://evil.example.com/metadata</saml:Issuer>".to_string(),
                &format!("<saml:Issuer>{DECONFL_IDP}</saml:Issuer>"),
                1,
            );
        let error = validate_saml_document_claims(&assertion_mutated, &deconflation_ctx())
            .expect_err("a wrong Assertion Issuer is refused");
        assert!(
            error.contains("Issuer does not match"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn scd_in_response_to_must_match_the_correlated_request() {
        let ctx = SamlValidationContext {
            expected_request_id: Some("_saml_staged".to_string()),
            ..deconflation_ctx()
        };
        // Missing InResponseTo where a request was staged.
        let error =
            validate_saml_document_claims(&deconflation_fixture().unsigned_document(), &ctx)
                .expect_err("no InResponseTo against a staged request is refused");
        assert!(
            error.contains("InResponseTo does not match"),
            "unexpected: {error}"
        );
        // A foreign InResponseTo.
        let mut fixture = deconflation_fixture();
        fixture.in_response_to = Some("_saml_other".to_string());
        let error = validate_saml_document_claims(&fixture.unsigned_document(), &ctx)
            .expect_err("a foreign InResponseTo is refused");
        assert!(
            error.contains("InResponseTo does not match"),
            "unexpected: {error}"
        );
        // The matching one passes.
        let mut fixture = deconflation_fixture();
        fixture.in_response_to = Some("_saml_staged".to_string());
        validate_saml_document_claims(&fixture.unsigned_document(), &ctx)
            .expect("the matching InResponseTo passes");
    }

    #[test]
    fn structural_wrapping_defenses_reject_adversarial_shapes() {
        let key = IDP_KEY.get_or_init(|| idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM));

        // A LEGITIMATE signed response with an unsigned ATTACKER assertion
        // appended as a sibling: any second Assertion is refused outright —
        // unsigned at the claim layer. (The sibling carries no Issuer so the
        // refusal demonstrably comes from the Assertion-count check, not the
        // duplicated-Issuer defense.)
        let attacker = r#"<saml:Assertion ID="_attacker" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Subject><saml:NameID>root@evil.example.com</saml:NameID></saml:Subject></saml:Assertion>"#;
        let legit_unsigned = deconflation_fixture().unsigned_document();
        let with_sibling =
            legit_unsigned.replace("</samlp:Response>", &format!("{attacker}</samlp:Response>"));
        let error = validate_saml_document_claims(&with_sibling, &deconflation_ctx())
            .expect_err("a second (attacker) Assertion is refused");
        assert!(
            error.contains("exactly one Assertion"),
            "unexpected: {error}"
        );
        // ...and SIGNED-LEGITIMATE-but-tampered: the attacker appends the
        // sibling to a genuinely signed document AFTER signing, so the
        // whole-document digest no longer matches — the signature gate
        // refuses it before any claim is read.
        let split = legit_unsigned
            .rfind("</samlp:Response>")
            .expect("Response root");
        let (prefix, suffix) = legit_unsigned.split_at(split);
        let legit_signed = idp::seal(prefix, suffix, key);
        let tampered_with_sibling =
            legit_signed.replace("</samlp:Response>", &format!("{attacker}</samlp:Response>"));
        let error = verify_saml_document_signature(&tampered_with_sibling, IDP_CERTIFICATE_PEM)
            .expect_err("an injected assertion breaks the signature");
        assert!(
            error.contains("signature"),
            "the injected sibling must fail the signature gate: {error}"
        );

        // Duplicate Assertion IDs (two Assertions sharing one ID) — refused.
        // The injected sibling carries no Issuer element so the refusal
        // demonstrably comes from the Assertion-count check.
        let document = deconflation_fixture()
            .unsigned_document()
            .replace("</saml:Assertion>", "</saml:Assertion><saml:Assertion ID=\"_resp_cov_dup\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\"><saml:Subject><saml:NameID>x@y.example.com</saml:NameID></saml:Subject></saml:Assertion>");
        let error = validate_saml_document_claims(&document, &deconflation_ctx())
            .expect_err("a second Assertion is refused");
        assert!(
            error.contains("exactly one Assertion"),
            "unexpected: {error}"
        );

        // Two NameIDs — refused.
        let document = deconflation_fixture().unsigned_document().replace(
            "</saml:NameID>",
            "</saml:NameID><saml:NameID>second@evil.example.com</saml:NameID>",
        );
        let error = validate_saml_document_claims(&document, &deconflation_ctx())
            .expect_err("a second NameID is refused");
        assert!(error.contains("exactly one NameID"), "unexpected: {error}");

        // A duplicated Issuer element at the response level — refused.
        let document = deconflation_fixture().unsigned_document().replacen(
            "<samlp:Status>",
            "<saml:Issuer>https://evil.example.com</saml:Issuer><samlp:Status>",
            1,
        );
        let error = validate_saml_document_claims(&document, &deconflation_ctx())
            .expect_err("a duplicated Issuer is refused");
        assert!(
            error.contains("multiple Issuer elements"),
            "unexpected: {error}"
        );

        // A missing SubjectConfirmationData — refused.
        let mut fixture = deconflation_fixture();
        fixture.include_scd = false;
        let error =
            validate_saml_document_claims(&fixture.unsigned_document(), &deconflation_ctx())
                .expect_err("a missing SubjectConfirmationData is refused");
        assert!(
            error.contains("exactly one SubjectConfirmationData"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn a_signature_scoped_to_a_subnode_is_refused_even_when_valid() {
        // Audit P2-7: a VALID signature whose ds:Reference targets a
        // sub-node (`URI="#_resp_cov"`) is refused by the signed-node
        // binding — claims parse only from whole-document signatures.
        let key = IDP_KEY.get_or_init(|| idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM));
        let document = deconflation_fixture().unsigned_document();
        let split = document
            .rfind("</samlp:Response>")
            .expect("fixture has a Response root");
        let (prefix, suffix) = document.split_at(split);
        let sealed = idp::seal(prefix, suffix, key);
        assert!(sealed.contains("URI=\"\""), "whole-document reference");

        let full_document = {
            // Re-seal with the targeted Reference so the signature is valid
            // over its own SignedInfo.
            idp::seal_with_targeted_reference(prefix, suffix, key, "_resp_cov")
        };
        let error = verify_saml_document_signature(&full_document, IDP_CERTIFICATE_PEM)
            .expect_err("a sub-node Reference is refused");
        assert!(
            error.contains("whole document") || error.contains("exactly one"),
            "unexpected: {error}"
        );
        // The whole-document seal still verifies (control).
        verify_saml_document_signature(&sealed, IDP_CERTIFICATE_PEM)
            .expect("the whole-document signature verifies");
    }

    #[test]
    fn expiration_is_fail_closed_on_missing_and_malformed_instants() {
        // Conditions rendered WITHOUT NotOnOrAfter: the required instant is
        // absent → refused (fail-closed). The Audience stays rendered, so
        // the failure demonstrably comes from the expiry check.
        let mut fixture = deconflation_fixture();
        fixture.not_on_or_after = None;
        let error =
            validate_saml_document_claims(&fixture.unsigned_document(), &deconflation_ctx())
                .expect_err("a missing NotOnOrAfter is refused (fail-closed)");
        assert!(
            error.contains("missing NotOnOrAfter"),
            "unexpected: {error}"
        );

        // A malformed NotOnOrAfter instant → refused, never skipped. The
        // LAST NotOnOrAfter in the rendered document is the Conditions'.
        let document = {
            let raw = deconflation_fixture().unsigned_document();
            let marker = "NotOnOrAfter=\"";
            let start = raw.rfind(marker).expect("NotOnOrAfter present") + marker.len();
            let end = raw[start..].find('"').expect("closing quote") + start;
            raw.replacen(&raw[start..end], "not-a-timestamp", 1)
        };
        let error = validate_saml_document_claims(&document, &deconflation_ctx())
            .expect_err("a malformed NotOnOrAfter is refused (fail-closed)");
        assert!(error.contains("malformed"), "unexpected: {error}");
    }

    // ═══════════════════════════════════════════════════════════════════
    // P3-9 outbound federation guard (SSRF) + P3-12 email assurance.
    // ═══════════════════════════════════════════════════════════════════

    /// The guard tests read the allowlist env; clear it so no sibling's
    /// mutation leaks into this process (nextest isolates per test).
    fn clear_federation_allowlist() {
        std::env::remove_var("SSO_FEDERATION_ALLOWLIST");
    }

    #[test]
    fn federation_guard_rejects_private_and_reserved_targets() {
        clear_federation_allowlist();
        // Loopback, RFC1918, link-local (the cloud metadata endpoint), the
        // unspecified address, carrier-grade NAT, IPv6 loopback / ULA /
        // link-local, and an IPv4-mapped loopback — EVERY resolved address
        // must be public.
        let blocked: &[&str] = &[
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.10",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ];
        for ip_str in blocked {
            let ip: std::net::IpAddr = ip_str.parse().expect("parse ip");
            let error = federation_guard_resolved("https://idp.evil.example.com", &[ip])
                .expect_err("a private/reserved target must be refused");
            assert!(
                error.contains("private/reserved"),
                "ip {ip_str}: unexpected refusal: {error}"
            );
        }

        // A MIXED answer — one public, one private — is refused (DNS
        // rebinding shape).
        let mixed = [
            "93.184.216.34".parse::<std::net::IpAddr>().unwrap(),
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        ];
        let error = federation_guard_resolved("https://idp.evil.example.com", &mixed)
            .expect_err("a mixed answer with one private address is refused");
        assert!(error.contains("private/reserved"), "unexpected: {error}");

        // A public address passes the pure half.
        let public = "93.184.216.34".parse::<std::net::IpAddr>().unwrap();
        let endpoint = federation_guard_resolved("https://idp.ok.example.com", &[public])
            .expect("a public target passes the pure guard");
        assert_eq!(endpoint.host, "idp.ok.example.com");
        assert_eq!(endpoint.url.scheme(), "https");
    }

    #[test]
    fn federation_guard_requires_https_outside_the_test_allowlist() {
        clear_federation_allowlist();
        let public = "93.184.216.34".parse::<std::net::IpAddr>().unwrap();
        let error = federation_guard_resolved("http://idp.ok.example.com", &[public])
            .expect_err("plaintext federation is refused");
        assert!(error.contains("HTTPS"), "unexpected: {error}");

        // With the loopback host allowlisted, the local mock IdP shape is
        // admitted — for THAT host only.
        std::env::set_var("SSO_FEDERATION_ALLOWLIST", "127.0.0.1");
        let loopback = "127.0.0.1".parse::<std::net::IpAddr>().unwrap();
        let endpoint = federation_guard_resolved("http://127.0.0.1:8080/discovery", &[loopback])
            .expect("the allowlisted loopback mock is admitted");
        assert_eq!(endpoint.addr.port(), 8080);
        // A different host stays refused even with the allowlist set.
        let error = federation_guard_resolved("http://idp.evil.example.com", &[public])
            .expect_err("a non-allowlisted host is still refused");
        assert!(error.contains("HTTPS"), "unexpected: {error}");
        clear_federation_allowlist();
    }

    #[test]
    fn oidc_email_claim_must_stand_on_its_own() {
        // Audit P3-12: `sub` never silently becomes the email.
        assert!(valid_oidc_email("alice@example.com"));
        assert!(valid_oidc_email("  alice@example.com  "));
        assert!(valid_oidc_email("alice+tag@sub.example.co.uk"));
        assert!(!valid_oidc_email(""), "empty");
        assert!(!valid_oidc_email("   "), "whitespace only");
        assert!(!valid_oidc_email("not-an-email"), "no @");
        assert!(!valid_oidc_email("@example.com"), "no local part");
        assert!(!valid_oidc_email("alice@"), "no domain");
        assert!(!valid_oidc_email("alice@example"), "no dot in the domain");
        assert!(!valid_oidc_email("a@b@c.com"), "two @ signs");
        assert!(
            !valid_oidc_email("alice exa mple@example.com"),
            "whitespace"
        );
        let long = format!("a{}@example.com", "b".repeat(250));
        assert!(!valid_oidc_email(&long), "over 254 chars");
    }

    #[test]
    fn sso_email_must_belong_to_the_configured_domain() {
        let mut config = SSOConfiguration {
            id: Uuid::new_v4(),
            tenant_id: "tenant_sso_email".into(),
            provider_type: "oidc".into(),
            enabled: true,
            domain: "Example.com".into(),
            metadata_url: None,
            idp_entity_id: None,
            sso_url: None,
            slo_url: None,
            certificate: None,
            private_key_encrypted: None,
            oidc_client_id: None,
            oidc_client_secret_encrypted: None,
            oidc_issuer: None,
            oidc_redirect_uri: None,
            oidc_scopes: None,
            attribute_mapping: None,
            enforce_sso: false,
            allow_idp_initiated: false,
            session_duration_hours: 8,
            created_at: None,
            updated_at: None,
        };
        // The configuration's own domain (case-insensitively).
        assert!(email_belongs_to_sso_domain("alice@example.com", &config));
        assert!(email_belongs_to_sso_domain("alice@EXAMPLE.com", &config));
        // A foreign domain without an explicit mapping is refused.
        assert!(!email_belongs_to_sso_domain(
            "alice@partner.example.com",
            &config
        ));
        // ...unless the configuration EXPLICITLY maps the domain.
        config.attribute_mapping = Some(serde_json::json!({
            "allowed_domains": ["Partner.Example.com"],
        }));
        assert!(email_belongs_to_sso_domain(
            "alice@partner.example.com",
            &config
        ));
        // An unrelated domain stays refused even with a mapping.
        assert!(!email_belongs_to_sso_domain(
            "alice@evil.example.com",
            &config
        ));
    }

    // ═══════════════════════════════════════════════════════════════════
    // DB-backed signed-SAML coverage: every parser-refusal arm, the
    // replay guard, the OIDC state machine and the session lifecycle,
    // driven against private clones of the canonical schema.
    // ═══════════════════════════════════════════════════════════════════

    async fn provision_sso(tag: &str) -> (SSOService, sqlx::PgPool) {
        if std::env::var("SSO_ENCRYPTION_KEY").is_err() {
            std::env::set_var("SSO_ENCRYPTION_KEY", "sso-coverage-key-0123456789");
        }
        if std::env::var("LOG_STREAM_ENCRYPTION_KEY").is_err() {
            std::env::set_var(
                "LOG_STREAM_ENCRYPTION_KEY",
                "log-stream-coverage-key-0123456789",
            );
        }
        let pool = migrator::test_support::fresh_canonical_pool(tag, &format!("sso_cov_{tag}"))
            .await
            .expect("provision canonical pool")
            .expect("TEST_DATABASE_URL must be configured for this suite");
        let config = Config::from_env().expect("Config::from_env in test env");
        (SSOService::new(pool.clone(), config), pool)
    }

    fn coverage_tenant(tag: &str) -> String {
        let unique = Uuid::new_v4().simple().to_string();
        let keep = 26usize.saturating_sub(tag.len() + 1);
        format!("{tag}_{}", &unique[..keep.min(unique.len())])
    }

    fn self_acs_url(service: &SSOService) -> String {
        service.config.sso.saml.acs_url.clone()
    }

    /// Seed the tenants row a generated test tenant id needs before any
    /// canonical `users` row can reference it (`users_tenant_id_fkey`).
    async fn seed_sso_tenant(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
             VALUES ($1, $2, $3, 'pro', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(format!("SSO Coverage Tenant {tenant}"))
        .bind(format!("sso-cov-{tenant}"))
        .execute(pool)
        .await
        .expect("seed SSO tenant");
    }

    async fn configure_saml_tenant(
        service: &SSOService,
        tenant: &str,
        domain: &str,
        with_certificate: bool,
    ) -> (String, String, String) {
        // The canonical users table carries a tenants FK: seed the tenant so
        // the callback's user provisioning succeeds.
        seed_sso_tenant(&service.db, tenant).await;
        // The IdP entity id must match the fixture Issuer; the Audience is
        // the SP entity id and the ACS URL comes from the service config
        // (the Destination / SubjectConfirmationData Recipient).
        let idp_entity_id = "https://idp.coverage.example.com/metadata".to_string();
        let sp_entity_id = service.config.sso.saml.entity_id.clone();
        let acs_url = self_acs_url(service);
        service
            .configure(SSOConfigureRequest {
                tenant_id: tenant.to_string(),
                provider_type: "saml".to_string(),
                domain: domain.to_string(),
                enabled: Some(true),
                idp_entity_id: Some(idp_entity_id.clone()),
                sso_url: Some("https://idp.coverage.example.com/sso".to_string()),
                certificate: if with_certificate {
                    Some(IDP_CERTIFICATE_PEM.to_string())
                } else {
                    None
                },
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_issuer: None,
                attribute_mapping: None,
                enforce_sso: Some(true),
                session_duration_hours: None,
            })
            .await
            .expect("configure SAML")
            .data
            .expect("configure returned a row");
        (idp_entity_id, sp_entity_id, acs_url)
    }

    /// Stage one SP-initiated AuthnRequest for InResponseTo correlation
    /// (audit P2-6): the ACS atomically consumes it on first use.
    async fn stage_saml_authn_request(service: &SSOService, domain: &str, request_id: &str) {
        let config = service
            .get_config_by_domain(domain)
            .await
            .expect("config by domain")
            .expect("configured domain");
        sqlx::query(
            "INSERT INTO ent_saml_authn_requests (request_id, tenant_id, domain, expires_at)
             VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind(request_id)
        .bind(&config.tenant_id)
        .bind(domain)
        .execute(&service.db)
        .await
        .expect("stage AuthnRequest");
    }

    async fn parse_fixture(
        service: &SSOService,
        domain: &str,
        fixture: &SamlFixture,
    ) -> Result<ValidatedSamlResponse, String> {
        // The fixture's InResponseTo names a freshly staged request so the
        // correlation gate (audit P2-6) passes; re-staging before every
        // parse keeps replay tests reaching the replay guard instead of the
        // correlation gate.
        if let Some(request_id) = fixture.in_response_to.as_deref() {
            stage_saml_authn_request(service, domain, request_id).await;
        }
        parse_fixture_unstaged(service, domain, fixture).await
    }

    /// Parse WITHOUT staging the fixture's InResponseTo — for the cases the
    /// correlation gate itself is the subject (a consumed or foreign stage).
    async fn parse_fixture_unstaged(
        service: &SSOService,
        domain: &str,
        fixture: &SamlFixture,
    ) -> Result<ValidatedSamlResponse, String> {
        let key = IDP_KEY.get_or_init(|| idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM));
        let document = fixture.render(key);
        service
            .parse_and_validate_saml_response(&document, domain)
            .await
    }

    static IDP_KEY: std::sync::OnceLock<idp::RsaPrivateKey> = std::sync::OnceLock::new();

    #[tokio::test]
    async fn signed_saml_response_is_validated_and_replays_are_rejected() {
        let tag = "signed_ok";
        let (service, _pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "signed-ok.coverage.example.com";
        let (idp_entity_id, sp_entity_id, acs_url) =
            configure_saml_tenant(&service, &tenant, domain, true).await;

        let fixture = SamlFixture::valid(&idp_entity_id, &sp_entity_id, &acs_url);
        let validated = parse_fixture(&service, domain, &fixture)
            .await
            .expect("a genuinely signed, correctly-formed response validates");
        assert_eq!(validated.name_id, "alice.smith@example.com");
        assert!(validated
            .attributes
            .iter()
            .any(|(name, value)| name == "email" && value == "alice.smith@example.com"));
        assert!(validated.attributes.iter().any(|(name, _)| name == "group"));

        // The same assertion id may never be consumed twice for the tenant.
        let replay = parse_fixture(&service, domain, &fixture)
            .await
            .expect_err("the second use of an assertion id is a replay");
        assert!(
            replay.contains("replay rejected"),
            "unexpected error: {replay}"
        );

        // A DIFFERENT tenant cannot burn the first tenant's assertion id...
        let other_tenant = coverage_tenant("signed_ok2");
        let (other_idp, other_sp, other_acs) = configure_saml_tenant(
            &service,
            &other_tenant,
            "signed-ok2.coverage.example.com",
            true,
        )
        .await;
        let mut other_fixture = SamlFixture::valid(&other_idp, &other_sp, &other_acs);
        other_fixture.assertion_id = fixture.assertion_id.clone();
        // ...the replay guard is per-tenant, so this is accepted — but a
        // second use for the OTHER tenant is still a replay.
        let _ = parse_fixture(&service, "signed-ok2.coverage.example.com", &other_fixture)
            .await
            .expect("replay protection is scoped per tenant");
        let replay_other =
            parse_fixture(&service, "signed-ok2.coverage.example.com", &other_fixture)
                .await
                .expect_err("second use for the other tenant is also a replay");
        assert!(replay_other.contains("replay rejected"));
    }

    #[tokio::test]
    async fn every_saml_refusal_arm_rejects_a_genuinely_signed_response() {
        let tag = "signed_refusals";
        let (service, _pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "refusals.coverage.example.com";
        let (idp_entity_id, sp_entity_id, acs_url) =
            configure_saml_tenant(&service, &tenant, domain, true).await;

        // Each case mutates one claim; the response stays properly SIGNED so
        // the refusal demonstrably comes from the claim check, not the
        // signature gate. (name, fixture mutation, expected error fragment)
        let assert_id = format!("_assertion_{}", Uuid::new_v4());
        type RefusalCase<'a> = (&'a str, Box<dyn Fn(&mut SamlFixture)>, &'a str);
        let cases: Vec<RefusalCase> = vec![
            (
                "failure status code",
                Box::new(move |f: &mut SamlFixture| {
                    f.status_value = "urn:oasis:names:tc:SAML:2.0:status:Responder".into();
                }),
                "StatusCode",
            ),
            (
                "issuer mismatch",
                Box::new(|f: &mut SamlFixture| f.issuer = "https://evil.example.com".into()),
                "Issuer does not match",
            ),
            (
                "missing issuer",
                Box::new(|f: &mut SamlFixture| f.issuer = String::new()),
                "missing Issuer",
            ),
            (
                "audience mismatch",
                Box::new(|f: &mut SamlFixture| f.audience = "https://evil.example.com/acs".into()),
                "AudienceRestriction does not match",
            ),
            (
                "missing audience restriction",
                Box::new(|f: &mut SamlFixture| f.include_audience = false),
                "missing AudienceRestriction",
            ),
            (
                "missing NameID",
                Box::new(|f: &mut SamlFixture| f.name_id = String::new()),
                "missing NameID",
            ),
            (
                "NameID sanitizes to empty (whitespace-only)",
                Box::new(|f: &mut SamlFixture| f.name_id = "   ".into()),
                "empty after sanitization",
            ),
            (
                "NameID over 256 chars sanitizes to empty",
                Box::new(|f: &mut SamlFixture| f.name_id = "x".repeat(257)),
                "empty after sanitization",
            ),
            (
                "missing assertion ID",
                Box::new(move |f: &mut SamlFixture| f.assertion_id = String::new()),
                "missing an ID",
            ),
            (
                "NotBefore in the future",
                Box::new(|f: &mut SamlFixture| {
                    f.not_before = Some(Utc::now() + chrono::Duration::minutes(30));
                }),
                "not yet valid",
            ),
            (
                "assertion expired",
                Box::new(|f: &mut SamlFixture| {
                    f.not_on_or_after = Some(Utc::now() - chrono::Duration::minutes(30));
                }),
                "has expired",
            ),
        ];
        let _ = assert_id;

        for (name, mutate, expected) in cases {
            let mut fixture = SamlFixture::valid(&idp_entity_id, &sp_entity_id, &acs_url);
            mutate(&mut fixture);
            let error = parse_fixture(&service, domain, &fixture)
                .await
                .err()
                .unwrap_or_default();
            assert!(
                error.contains(expected),
                "case {name}: expected error containing '{expected}', got '{error}'"
            );
        }
    }

    #[tokio::test]
    async fn signed_saml_gate_itself_rejects_unsigned_and_tampered_documents() {
        let tag = "signed_gate";
        let (service, _pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "gate.coverage.example.com";
        let (idp_entity_id, sp_entity_id, acs_url) =
            configure_saml_tenant(&service, &tenant, domain, true).await;

        // Unsigned: refused before any parsing.
        let mut fixture = SamlFixture::valid(&idp_entity_id, &sp_entity_id, &acs_url);
        fixture.include_signature = false;
        let unsigned_error = parse_fixture(&service, domain, &fixture)
            .await
            .expect_err("unsigned must be refused");
        assert!(
            unsigned_error.contains("signature"),
            "unsigned must be refused at the signature gate: {unsigned_error}"
        );

        // Tampered: text inserted into the digest value AFTER signing
        // breaks the reference digest — the DsigStatus::Invalid arm.
        let key = IDP_KEY.get_or_init(|| idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM));
        let mut signed_case = SamlFixture::valid(&idp_entity_id, &sp_entity_id, &acs_url);
        signed_case.name_id = "tamper-check@example.com".into();
        let signed_document = signed_case.render(key);
        let marker = "<ds:DigestValue>";
        let pos = signed_document
            .find(marker)
            .expect("signed doc has a digest");
        let mut tampered = signed_document.clone();
        // Flip the first digest character IN PLACE: same length, so the
        // signature still parses and the failure is a real digest mismatch.
        let digest_start = pos + marker.len();
        let original_char = tampered.as_bytes()[digest_start] as char;
        let replacement = if original_char == 'A' { 'B' } else { 'A' };
        tampered.replace_range(digest_start..digest_start + 1, &replacement.to_string());
        assert_ne!(tampered, signed_document, "tampering must change the doc");
        let tampered_error = service
            .parse_and_validate_saml_response(&tampered, domain)
            .await
            .expect_err("tampered digest must be refused");
        assert!(
            tampered_error.contains("signature verification failed"),
            "tampered digest must be Invalid: {tampered_error}"
        );
        // The untouched document still validates (the gate is exact) — its
        // InResponseTo correlates against a fresh stage (audit P2-6).
        stage_saml_authn_request(
            &service,
            domain,
            signed_case
                .in_response_to
                .as_deref()
                .expect("fixture InResponseTo"),
        )
        .await;
        let valid = service
            .parse_and_validate_saml_response(&signed_document, domain)
            .await;
        assert!(valid.is_ok(), "the untouched signed document must validate");

        // Malformed XML is refused (parse error before any claim logic).
        let malformed_error = service
            .parse_and_validate_saml_response("<not-xml", domain)
            .await
            .expect_err("malformed XML must be refused");
        assert!(
            malformed_error.contains("signature") || malformed_error.contains("parse"),
            "malformed XML: {malformed_error}"
        );
    }

    #[tokio::test]
    async fn saml_without_a_configured_certificate_is_refused() {
        let tag = "signed_nocert";
        let (service, _pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "nocert.coverage.example.com";
        let (idp_entity_id, sp_entity_id, acs_url) =
            configure_saml_tenant(&service, &tenant, domain, false).await;

        let fixture = SamlFixture::valid(&idp_entity_id, &sp_entity_id, &acs_url);
        let error = parse_fixture(&service, domain, &fixture)
            .await
            .expect_err("a signed response without a configured cert must be refused");
        assert!(
            error.contains("certificate is not configured"),
            "unexpected: {error}"
        );
    }

    #[tokio::test]
    async fn in_response_to_correlation_is_enforced() {
        let tag = "saml_irt";
        let (service, pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "irt.coverage.example.com";
        let (idp_entity_id, sp_entity_id, acs_url) =
            configure_saml_tenant(&service, &tenant, domain, true).await;

        // 1. An unsolicited (IdP-initiated) response is refused while the
        //    configuration does not allow it.
        let mut unsolicited = SamlFixture::valid(&idp_entity_id, &sp_entity_id, &acs_url);
        unsolicited.in_response_to = None;
        let error = parse_fixture(&service, domain, &unsolicited)
            .await
            .expect_err("unsolicited response refused");
        assert!(error.contains("unsolicited"), "unexpected: {error}");

        // 2. A response correlating against a staged request validates, and
        //    the stage is consumed exactly once.
        let solicited = SamlFixture::valid(&idp_entity_id, &sp_entity_id, &acs_url);
        let request_id = solicited.in_response_to.clone().expect("InResponseTo");
        stage_saml_authn_request(&service, domain, &request_id).await;
        parse_fixture(&service, domain, &solicited)
            .await
            .expect("the solicited response validates");
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ent_saml_authn_requests WHERE request_id = $1",
        )
        .bind(&request_id)
        .fetch_one(&pool)
        .await
        .expect("count stages");
        assert_eq!(remaining, 0, "the consumed stage is gone");

        // 3. A second response re-using the CONSUMED request id is refused
        //    (unsolicited again — the stage is gone).
        let mut replayed_request = SamlFixture::valid(&idp_entity_id, &sp_entity_id, &acs_url);
        replayed_request.in_response_to = Some(request_id.clone());
        replayed_request.assertion_id = format!("_assertion_{}", Uuid::new_v4());
        let error = parse_fixture_unstaged(&service, domain, &replayed_request)
            .await
            .expect_err("a consumed InResponseTo is refused");
        assert!(
            error.contains("does not match an outstanding request"),
            "unexpected: {error}"
        );

        // 4. An EXPIRED stage is dead.
        let late = SamlFixture::valid(&idp_entity_id, &sp_entity_id, &acs_url);
        let late_request_id = late.in_response_to.clone().expect("InResponseTo");
        sqlx::query(
            "INSERT INTO ent_saml_authn_requests (request_id, tenant_id, domain, expires_at)
             VALUES ($1, $2, $3, NOW() - INTERVAL '1 minute')",
        )
        .bind(&late_request_id)
        .bind(&tenant)
        .bind(domain)
        .execute(&pool)
        .await
        .expect("stage expired request");
        let error = parse_fixture(&service, domain, &late)
            .await
            .expect_err("an expired stage is refused");
        assert!(
            error.contains("does not match an outstanding request"),
            "unexpected: {error}"
        );

        // 5. A request staged for ANOTHER tenant never correlates.
        let other_tenant = coverage_tenant(tag);
        let other_domain = "irt-other.coverage.example.com";
        let (other_idp, other_sp, other_acs) =
            configure_saml_tenant(&service, &other_tenant, other_domain, true).await;
        let cross_tenant = SamlFixture::valid(&other_idp, &other_sp, &other_acs);
        let cross_request_id = cross_tenant.in_response_to.clone().expect("InResponseTo");
        // Stage it for the FIRST tenant's domain; present it on the other.
        stage_saml_authn_request(&service, domain, &cross_request_id).await;
        let error = parse_fixture(&service, other_domain, &cross_tenant)
            .await
            .expect_err("a foreign-tenant stage is refused");
        assert!(
            error.contains("does not match an outstanding request")
                || error.contains("does not belong to this domain"),
            "unexpected: {error}"
        );

        // 6. An explicitly IdP-initiated configuration accepts the
        //    unsolicited response.
        sqlx::query(
            "UPDATE ent_sso_configurations SET allow_idp_initiated = true WHERE tenant_id = $1",
        )
        .bind(&other_tenant)
        .execute(&pool)
        .await
        .expect("allow IdP-initiated");
        let mut idp_initiated = SamlFixture::valid(&other_idp, &other_sp, &other_acs);
        idp_initiated.in_response_to = None;
        parse_fixture(&service, other_domain, &idp_initiated)
            .await
            .expect("an explicitly allowed IdP-initiated response validates");
    }

    #[tokio::test]
    async fn oidc_state_machine_covers_redis_db_fallback_and_error_arms() {
        let tag = "oidc_state";
        let (service, pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "oidc.coverage.example.com";
        // Audit P3-10: the authorize URL comes from DISCOVERY. The mock IdP
        // advertises a NONSTANDARD authorization_endpoint, so a redirect to
        // it proves the flow consumed discovery rather than concatenating
        // `{issuer}/authorize`.
        let issuer = start_mock_oidc_idp().await;
        service
            .configure(SSOConfigureRequest {
                tenant_id: tenant.clone(),
                provider_type: "oidc".to_string(),
                domain: domain.to_string(),
                enabled: Some(true),
                idp_entity_id: None,
                sso_url: None,
                certificate: None,
                oidc_client_id: Some("client-123".to_string()),
                oidc_client_secret: Some("shhh".to_string()),
                oidc_issuer: Some(issuer.clone()),
                attribute_mapping: None,
                enforce_sso: Some(false),
                session_duration_hours: None,
            })
            .await
            .expect("configure OIDC");

        // Non-OIDC providers and unknown domains are refused.
        let saml_service_domain = "oidc-saml.coverage.example.com";
        service
            .configure(SSOConfigureRequest {
                tenant_id: coverage_tenant(tag),
                provider_type: "saml".to_string(),
                domain: saml_service_domain.to_string(),
                enabled: Some(true),
                idp_entity_id: None,
                sso_url: None,
                certificate: None,
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_issuer: None,
                attribute_mapping: None,
                enforce_sso: None,
                session_duration_hours: None,
            })
            .await
            .expect("configure SAML-only tenant");
        let wrong_provider = service
            .initiate_oidc_login(saml_service_domain, None)
            .await
            .expect("query works");
        assert!(
            !wrong_provider.success,
            "SAML provider is not an OIDC provider"
        );
        let unknown = service
            .initiate_oidc_login("no-such-oidc.example.com", None)
            .await
            .expect("query");
        assert!(!unknown.success, "unknown domain has no OIDC config");

        // Without a Redis pool the state falls back to the durable table.
        let redirect = service
            .initiate_oidc_login(domain, None)
            .await
            .expect("initiate works")
            .data
            .expect("redirect");
        assert!(
            redirect.redirect_url.starts_with(&format!(
                "{issuer}/oidc-auth-nonstandard?client_id=client-123"
            )),
            "the authorize URL is discovery's (nonstandard) authorization_endpoint: {}",
            redirect.redirect_url
        );
        assert!(redirect.redirect_url.contains("code_challenge_method=S256"));
        let state = redirect.request_id.clone();
        let from_db = service
            .validate_oidc_state(&state)
            .await
            .expect("validate state")
            .expect("state exists in the durable fallback");
        assert_eq!(from_db.domain, domain);
        assert!(!from_db.code_verifier.is_empty());
        // Single use: the DELETE..RETURNING makes the second lookup a miss.
        let replayed = service
            .validate_oidc_state(&state)
            .await
            .expect("validate again");
        assert!(replayed.is_none(), "a consumed state never validates twice");

        // With a Redis pool the state round-trips through `oidc_state:*`.
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let with_redis = SSOService::with_redis(pool.clone(), redis.clone(), new_sso_config());
        let redirect = with_redis
            .initiate_oidc_login(domain, None)
            .await
            .expect("initiate with redis")
            .data
            .expect("redirect");
        let state = redirect.request_id.clone();
        let stored: Option<String> = {
            let mut conn = redis.get().await.expect("redis conn");
            conn.get(format!("oidc_state:{state}")).await.expect("get")
        };
        assert!(stored.is_some(), "the state is staged in redis");
        let from_redis = with_redis
            .validate_oidc_state(&state)
            .await
            .expect("validate from redis")
            .expect("state exists in redis");
        assert_eq!(from_redis.tenant_id.as_deref(), Some(tenant.as_str()));
        // Consumed: the key is deleted, and the DB fallback misses too.
        let consumed: Option<String> = {
            let mut conn = redis.get().await.expect("redis conn");
            conn.get(format!("oidc_state:{state}")).await.expect("get")
        };
        assert!(consumed.is_none(), "redis state is single-use");
        let _ = with_redis.validate_oidc_state(&state).await;

        // Malformed staged JSON and a missing code_verifier are honest
        // errors, not silent fallbacks.
        let mut conn = redis.get().await.expect("redis conn");
        let _: () = conn
            .set_ex("oidc_state:cov_malformed", "not-json", 60)
            .await
            .expect("stage malformed");
        let _: () = conn
            .set_ex(
                "oidc_state:cov_no_verifier",
                r#"{"domain":"x.example.com"}"#,
                60,
            )
            .await
            .expect("stage no-verifier");
        drop(conn);
        let malformed = with_redis
            .validate_oidc_state("cov_malformed")
            .await
            .expect_err("malformed JSON fails");
        assert!(malformed.contains("Parse state"), "unexpected: {malformed}");
        let no_verifier = with_redis
            .validate_oidc_state("cov_no_verifier")
            .await
            .expect_err("missing verifier fails");
        assert!(
            no_verifier.contains("code_verifier"),
            "unexpected: {no_verifier}"
        );
    }

    /// Audit P3-11: the Redis state consumption is GETDEL — ONE atomic
    /// server operation. Twenty concurrent callbacks race the same state:
    /// EXACTLY ONE sees it, the other nineteen are refused.
    #[tokio::test]
    async fn oidc_state_consumption_is_atomic_under_concurrency() {
        let tag = "oidc_state_barrier";
        let (service, _pool) = provision_sso(tag).await;
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let service = SSOService::with_redis(service.db.clone(), redis.clone(), new_sso_config());

        // Stage the state the way initiate_oidc_login does.
        let state = "cov_barrier_state".to_string();
        let staged = serde_json::json!({
            "code_verifier": "barrier-verifier",
            "domain": "barrier.coverage.example.com",
            "tenant_id": "tenant_barrier",
            "return_to": Option::<String>::None,
            "created_at": Utc::now().timestamp(),
        });
        {
            let mut conn = redis.get().await.expect("redis conn");
            let _: () = conn
                .set_ex(format!("oidc_state:{state}"), staged.to_string(), 300)
                .await
                .expect("stage state");
        }

        // Twenty tasks race the same single-use state.
        const RACERS: usize = 20;
        let mut handles = Vec::with_capacity(RACERS);
        for _ in 0..RACERS {
            let service =
                SSOService::with_redis(service.db.clone(), redis.clone(), new_sso_config());
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                service.validate_oidc_state(&state).await
            }));
        }
        let mut winners = 0usize;
        let mut losers = 0usize;
        for handle in handles {
            let result = handle.await.expect("task joins");
            match result.expect("validate") {
                Some(_) => winners += 1,
                None => losers += 1,
            }
        }
        assert_eq!(winners, 1, "exactly one callback wins the state");
        assert_eq!(losers, RACERS - 1, "every other callback is refused");
    }

    /// A minimal in-process OIDC discovery IdP (audit P3-10/P3-9 test
    /// infrastructure): bound on 127.0.0.1 over plain HTTP and admitted by
    /// the federation allowlist, advertising a NONSTANDARD
    /// authorization_endpoint. The served document's issuer matches the
    /// configured issuer exactly, as the guard requires.
    async fn start_mock_oidc_idp() -> String {
        if std::env::var("SSO_FEDERATION_ALLOWLIST").is_err() {
            std::env::set_var("SSO_FEDERATION_ALLOWLIST", "127.0.0.1");
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock idp");
        let port = listener.local_addr().expect("mock idp addr").port();
        let issuer = format!("http://127.0.0.1:{port}");
        let discovery = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oidc-auth-nonstandard"),
            "token_endpoint": format!("{issuer}/oidc-token"),
            "jwks_uri": format!("{issuer}/oidc-jwks"),
        });
        let body = serde_json::to_string(&discovery).expect("serialize discovery");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(stream) => stream,
                    Err(_) => break,
                };
                use std::io::{Read as _, Write as _};
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        issuer
    }

    fn new_sso_config() -> Config {
        Config::from_env().expect("Config::from_env in test env")
    }

    #[tokio::test]
    async fn sso_session_lifecycle_covers_new_and_returning_users() {
        let tag = "sso_session";
        let (service, pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "session.coverage.example.com";
        let (_idp, _sp, _acs) = configure_saml_tenant(&service, &tenant, domain, true).await;
        let config = service
            .get_config_by_domain(domain)
            .await
            .expect("config by domain")
            .expect("configured domain");

        // First login: a new user with a session bound to the configured
        // duration.
        let first = service
            .handle_saml_callback(
                &config,
                FederationIdentity {
                    email: "carol@example.com",
                    display_name: Some("Carol"),
                    external_user_id: "carol-external-id",
                    groups: Some(serde_json::json!(["admins"])),
                    attributes: None,
                },
                None,
            )
            .await
            .expect("callback works")
            .data
            .expect("session result");
        assert!(first.is_new_user, "the first login is a new user");
        let token = first.session.session_token.clone();

        // The token validates and stamps last activity.
        let session = service
            .validate_session(&token)
            .await
            .expect("validate")
            .expect("live session");
        assert_eq!(session.email, "carol@example.com");

        // Second login for the same external id: not a new user — the
        // durable ent_sso_identities binding decides, never session history.
        let second = service
            .handle_saml_callback(
                &config,
                FederationIdentity {
                    email: "carol@example.com",
                    display_name: Some("Carol"),
                    external_user_id: "carol-external-id",
                    groups: None,
                    attributes: None,
                },
                None,
            )
            .await
            .expect("callback works")
            .data
            .expect("session result");
        assert!(!second.is_new_user, "the second login is a returning user");

        // Expired sessions validate to nothing and are swept.
        sqlx::query("UPDATE ent_sso_sessions SET expires_at = NOW() - INTERVAL '1 hour'")
            .execute(&pool)
            .await
            .expect("expire sessions");
        let expired = service
            .validate_session(&token)
            .await
            .expect("validate")
            .is_none();
        assert!(expired, "an expired session never validates");
        let swept = service.cleanup_expired_sessions().await.expect("cleanup");
        assert!(swept >= 2, "both carol sessions were swept, got {swept}");
        let left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ent_sso_sessions WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(left, 0);

        // OIDC callbacks create sessions too.
        let oidc_session = service
            .handle_oidc_callback(
                &config,
                FederationIdentity {
                    email: "dave@example.com",
                    display_name: None,
                    external_user_id: "dave-external-id",
                    groups: None,
                    attributes: None,
                },
                None,
            )
            .await
            .expect("oidc callback")
            .data
            .expect("session");
        assert!(oidc_session.is_new_user);
    }

    #[tokio::test]
    async fn cleanup_expired_sessions_degrades_when_the_table_is_missing() {
        let tag = "sso_cleanup_missing";
        let (service, pool) = provision_sso(tag).await;
        sqlx::query("ALTER TABLE ent_sso_sessions RENAME TO ent_sso_sessions_gone")
            .execute(&pool)
            .await
            .expect("break table");
        let swept = service
            .cleanup_expired_sessions()
            .await
            .expect("a missing table degrades to a no-op sweep");
        assert_eq!(swept, 0);
        sqlx::query("ALTER TABLE ent_sso_sessions_gone RENAME TO ent_sso_sessions")
            .execute(&pool)
            .await
            .expect("restore table");
    }

    #[tokio::test]
    async fn tenant_enforces_sso_covers_every_lookup_arm() {
        let tag = "sso_enforce";
        let (service, pool) = provision_sso(tag).await;
        let enforcing = coverage_tenant(tag);
        let relaxed = coverage_tenant(tag);

        // Enforcing and non-enforcing rows.
        for (tenant, enforce) in [(&enforcing, true), (&relaxed, false)] {
            service
                .configure(SSOConfigureRequest {
                    tenant_id: tenant.to_string(),
                    provider_type: "saml".to_string(),
                    domain: format!("{tenant}.enforce.example.com"),
                    enabled: Some(true),
                    idp_entity_id: None,
                    sso_url: None,
                    certificate: None,
                    oidc_client_id: None,
                    oidc_client_secret: None,
                    oidc_issuer: None,
                    attribute_mapping: None,
                    enforce_sso: Some(enforce),
                    session_duration_hours: None,
                })
                .await
                .expect("configure");
        }
        assert!(service
            .tenant_enforces_sso(&enforcing)
            .await
            .expect("lookup"));
        assert!(!service.tenant_enforces_sso(&relaxed).await.expect("lookup"));

        // Audit P1-2: MULTIPLE configuration rows per tenant (one per
        // domain) — the bool_or aggregate is deterministic where the old
        // `LIMIT 1` pick was arbitrary. A relaxed domain cannot hide an
        // enforcing one, and an enforcing domain cannot hide behind a
        // relaxed one.
        service
            .configure(SSOConfigureRequest {
                tenant_id: enforcing.clone(),
                provider_type: "saml".to_string(),
                domain: format!("{enforcing}.enforce-second.example.com"),
                enabled: Some(true),
                idp_entity_id: None,
                sso_url: None,
                certificate: None,
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_issuer: None,
                attribute_mapping: None,
                enforce_sso: Some(false),
                session_duration_hours: None,
            })
            .await
            .expect("configure second domain");
        assert!(
            service
                .tenant_enforces_sso(&enforcing)
                .await
                .expect("lookup"),
            "one enforcing row among several must enforce"
        );
        service
            .configure(SSOConfigureRequest {
                tenant_id: relaxed.clone(),
                provider_type: "saml".to_string(),
                domain: format!("{relaxed}.relaxed-second.example.com"),
                enabled: Some(true),
                idp_entity_id: None,
                sso_url: None,
                certificate: None,
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_issuer: None,
                attribute_mapping: None,
                enforce_sso: Some(true),
                session_duration_hours: None,
            })
            .await
            .expect("configure second domain");
        assert!(
            service.tenant_enforces_sso(&relaxed).await.expect("lookup"),
            "one enforcing row among several must enforce"
        );
        // The free function agrees with the method.
        assert!(enterprise_sso_enforces(&pool, &enforcing).await);
        // No row: the gate stays open.
        assert!(!enterprise_sso_enforces(&pool, "no-such-enforce-tenant").await);

        // Missing table (42P01): the gate degrades open instead of locking
        // every tenant out.
        sqlx::query("ALTER TABLE ent_sso_configurations RENAME TO ent_sso_configurations_gone")
            .execute(&pool)
            .await
            .expect("break table");
        assert!(!enterprise_sso_enforces(&pool, &enforcing).await);
        sqlx::query("ALTER TABLE ent_sso_configurations_gone RENAME TO ent_sso_configurations")
            .execute(&pool)
            .await
            .expect("restore table");

        // Any other database failure surfaces as Err (broken pool).
        let broken = crate::config::Config::from_env().expect("config");
        let broken_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(300))
            .connect_lazy("postgresql://127.0.0.1:5432/enterprise_no_such_db_cov")
            .expect("lazy pool");
        let error = tenant_enforces_sso(&broken_pool, &enforcing)
            .await
            .expect_err("a broken pool is an error, not an open gate");
        assert!(error.contains("Check enforce_sso"), "unexpected: {error}");
        let _ = broken;
    }

    async fn enterprise_sso_enforces(pool: &sqlx::PgPool, tenant: &str) -> bool {
        tenant_enforces_sso(pool, tenant)
            .await
            .expect("lookup works")
    }

    #[tokio::test]
    async fn configuration_lookup_and_domain_gates_cover_their_arms() {
        let tag = "sso_lookup";
        let (service, pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "lookup.coverage.example.com";
        let _ = configure_saml_tenant(&service, &tenant, domain, true).await;

        // Found and not-found configuration lookups.
        let found = service
            .get_configuration(&tenant)
            .await
            .expect("lookup works");
        assert!(found.data.is_some(), "the configured tenant is found");
        let missing = service
            .get_configuration("no-such-lookup-tenant")
            .await
            .expect("lookup works");
        assert!(!missing.success, "an unconfigured tenant is NOT_FOUND");

        // Enabled-domain lookup finds the row...
        let by_domain = service
            .get_config_by_domain(domain)
            .await
            .expect("domain lookup");
        assert!(by_domain.is_some());
        // Audit F11 (verifier repair): the lookup is CASE-INSENSITIVE —
        // `WHERE LOWER(domain) = LOWER($1)`. A configuration saved as
        // `Example.com` must stay reachable via `example.com` RelayState
        // (the email-side checks have lowercased all along); an exact-match
        // regression silently breaks the flow for the other case.
        let mixed_case = service
            .get_config_by_domain("LOOKUP.COVERAGE.Example.com")
            .await
            .expect("case-insensitive domain lookup");
        assert!(
            mixed_case.is_some(),
            "a domain must resolve regardless of the case it is presented in"
        );
        // ...disabled rows never match...
        sqlx::query("UPDATE ent_sso_configurations SET enabled = false WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("disable");
        let disabled = service
            .get_config_by_domain(domain)
            .await
            .expect("domain lookup");
        assert!(
            disabled.is_none(),
            "a disabled config is invisible by domain"
        );
        sqlx::query("UPDATE ent_sso_configurations SET enabled = true WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("re-enable");
        // ...and a missing table degrades to "no config for domain".
        sqlx::query("ALTER TABLE ent_sso_configurations RENAME TO ent_sso_configurations_gone")
            .execute(&pool)
            .await
            .expect("break table");
        let gone = service
            .get_config_by_domain(domain)
            .await
            .expect("missing table degrades to None");
        assert!(gone.is_none());
        sqlx::query("ALTER TABLE ent_sso_configurations_gone RENAME TO ent_sso_configurations")
            .execute(&pool)
            .await
            .expect("restore table");
    }

    // ═══════════════════════════════════════════════════════════════════
    // P1-3 canonical-session plumbing: the sanitized post-login redirect
    // target (open-redirect defense) and the am_session mint itself.
    // ═══════════════════════════════════════════════════════════════════

    const JWT_TEST_PRIVATE_PEM: &str = include_str!("../tests/keys/test_rsa_private.pem");
    const JWT_TEST_PUBLIC_PEM: &str = include_str!("../tests/keys/test_rsa_public.pem");

    #[test]
    fn return_to_is_sanitized_to_same_origin_paths() {
        // Same-origin absolute paths survive untouched.
        assert_eq!(sanitize_return_to(Some("/inbox")), "/inbox");
        assert_eq!(
            sanitize_return_to(Some("/domains/example.com/dns?tab=records")),
            "/domains/example.com/dns?tab=records"
        );
        assert_eq!(sanitize_return_to(Some("  /settings  ")), "/settings");

        // EVERYTHING else falls back to /dashboard: empty, control bytes,
        // off-origin absolute URLs, protocol-relative redirects, backslash
        // tricks, and traversal.
        assert_eq!(sanitize_return_to(None), "/dashboard");
        assert_eq!(sanitize_return_to(Some("")), "/dashboard");
        assert_eq!(sanitize_return_to(Some("   ")), "/dashboard");
        assert_eq!(
            sanitize_return_to(Some("https://evil.example.com")),
            "/dashboard"
        );
        assert_eq!(
            sanitize_return_to(Some("javascript:alert(1)")),
            "/dashboard"
        );
        assert_eq!(sanitize_return_to(Some("//evil.example.com")), "/dashboard");
        assert_eq!(
            sanitize_return_to(Some("/\\evil.example.com")),
            "/dashboard"
        );
        assert_eq!(sanitize_return_to(Some("/safe/../../evil")), "/dashboard");
        assert_eq!(
            sanitize_return_to(Some("/inbox\u{0007}")),
            "/dashboard",
            "control characters never ride into a Location header"
        );
    }

    #[tokio::test]
    async fn canonical_session_mint_matches_the_console_cookie_shape() {
        if std::env::var("SSO_ENCRYPTION_KEY").is_err() {
            std::env::set_var("SSO_ENCRYPTION_KEY", "sso-coverage-key-0123456789");
        }
        // A DB-free service: minting never touches the pool.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:unused@127.0.0.1:1/mint_only")
            .expect("lazy pool");
        let mut config = new_sso_config();

        // Without the shared signing key the mint degrades to None — the
        // enterprise bearer session still exists, no console cookie is
        // claimed.
        config.jwt_private_key_pem = String::new();
        let service = SSOService::new(pool.clone(), config);
        assert!(service
            .mint_canonical_session("u", "t", "member", 8, Some("/inbox"))
            .is_none());

        // With the key: the SAME cookie shape the console password login
        // writes, a sanitized redirect, and a verifiable RS256 token.
        let mut config = new_sso_config();
        config.jwt_private_key_pem = JWT_TEST_PRIVATE_PEM.to_string();
        let service = SSOService::new(pool, config);
        let minted = service
            .mint_canonical_session(
                "018f0ac4-1111-7000-8000-000000000001",
                "tenant_mint",
                "admin",
                8,
                Some("//evil.example.com"),
            )
            .expect("the key mints a canonical session");
        assert_eq!(minted.user_id, "018f0ac4-1111-7000-8000-000000000001");
        assert_eq!(minted.tenant_id, "tenant_mint");
        assert_eq!(
            minted.return_to, "/dashboard",
            "off-origin return_to falls back"
        );
        assert!(
            minted.cookie.starts_with("am_session="),
            "the canonical cookie name: {}",
            minted.cookie
        );
        for attribute in ["HttpOnly", "Path=/", "SameSite=Strict"] {
            assert!(
                minted.cookie.contains(attribute),
                "cookie must carry {attribute}: {}",
                minted.cookie
            );
        }

        // The minted token decodes against the deployment's PUBLIC key with
        // the canonical claim shape (sub/tenant_id/scopes/typ=session). The
        // claims type itself is Serialize-only (it mints, it never accepts),
        // so the test decodes into its own mirror.
        #[derive(serde::Deserialize)]
        struct MintedClaims {
            sub: String,
            tenant_id: String,
            scopes: Vec<String>,
            typ: Option<String>,
        }
        let token = minted
            .cookie
            .split(';')
            .next()
            .and_then(|pair| pair.strip_prefix("am_session="))
            .expect("cookie carries the token");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let decoded = jsonwebtoken::decode::<MintedClaims>(
            token,
            &jsonwebtoken::DecodingKey::from_rsa_pem(JWT_TEST_PUBLIC_PEM.as_bytes())
                .expect("public key"),
            &validation,
        )
        .expect("the minted session JWT verifies");
        assert_eq!(decoded.claims.sub, "018f0ac4-1111-7000-8000-000000000001");
        assert_eq!(decoded.claims.tenant_id, "tenant_mint");
        assert_eq!(decoded.claims.typ.as_deref(), Some("session"));
        assert!(
            decoded.claims.scopes.iter().any(|scope| scope == "*"),
            "an admin role carries the admin scope set"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Audit F6: the canonical session lifetime follows the tenant's
    // configured `session_duration_hours`, not a hardcoded 8 hours.
    // ═══════════════════════════════════════════════════════════════════

    fn minting_service() -> SSOService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:unused@127.0.0.1:1/mint_only")
            .expect("lazy pool");
        let mut config = new_sso_config();
        config.jwt_private_key_pem = JWT_TEST_PRIVATE_PEM.to_string();
        SSOService::new(pool, config)
    }

    fn cookie_max_age(cookie: &str) -> i64 {
        cookie
            .split(';')
            .find_map(|attribute| attribute.trim().strip_prefix("Max-Age="))
            .and_then(|value| value.parse().ok())
            .unwrap_or(-1)
    }

    #[tokio::test]
    async fn one_hour_configuration_yields_a_one_hour_cookie() {
        let service = minting_service();
        let minted = service
            .mint_canonical_session("u-1h", "tenant_1h", "member", 1, None)
            .expect("the key mints a canonical session");
        assert_eq!(
            cookie_max_age(&minted.cookie),
            3600,
            "a 1h session_duration_hours must give a 1h cookie, got {}",
            minted.cookie
        );
    }

    #[tokio::test]
    async fn twenty_four_hour_configuration_is_not_cut_to_eight() {
        let service = minting_service();
        let minted = service
            .mint_canonical_session("u-24h", "tenant_24h", "admin", 24, None)
            .expect("the key mints a canonical session");
        assert_eq!(cookie_max_age(&minted.cookie), 24 * 3600);
    }

    #[tokio::test]
    async fn degenerate_and_oversized_durations_are_clamped() {
        let service = minting_service();
        // A zero/negative policy must not mint an immediately-expiring cookie.
        let minted = service
            .mint_canonical_session("u-0h", "tenant_0h", "member", 0, None)
            .expect("the key mints a canonical session");
        assert_eq!(cookie_max_age(&minted.cookie), 3600);
        // A runaway policy is clamped to the 24h maximum.
        let minted = service
            .mint_canonical_session("u-999h", "tenant_999h", "member", 999, None)
            .expect("the key mints a canonical session");
        assert_eq!(cookie_max_age(&minted.cookie), 24 * 3600);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Audit F2: the SAML ACS applies the same email assurance as OIDC via
    // `validate_asserted_email` — the single identity-trust bar both
    // federations resolve sessions through.
    // ═══════════════════════════════════════════════════════════════════

    fn sso_config_for_domain(domain: &str) -> SSOConfiguration {
        SSOConfiguration {
            id: Uuid::new_v4(),
            tenant_id: "tenant_f2".to_string(),
            provider_type: "saml".to_string(),
            enabled: true,
            domain: domain.to_string(),
            metadata_url: None,
            idp_entity_id: None,
            sso_url: None,
            slo_url: None,
            certificate: None,
            private_key_encrypted: None,
            oidc_client_id: None,
            oidc_client_secret_encrypted: None,
            oidc_issuer: None,
            oidc_redirect_uri: None,
            oidc_scopes: None,
            attribute_mapping: None,
            enforce_sso: false,
            allow_idp_initiated: false,
            session_duration_hours: 8,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        }
    }

    #[test]
    fn saml_assertion_of_a_foreign_domain_email_is_refused() {
        // The takeover shape from the audit: a SAML IdP (or anyone controlling
        // an account on a mis-scoped IdP) asserting `victim@anydomain.com`
        // must be refused before `resolve_or_provision_sso_user` can link the
        // asserted email onto a same-tenant local account.
        let config = sso_config_for_domain("example.com");
        let error = validate_asserted_email("victim@anydomain.com", &config)
            .expect_err("a cross-domain asserted email must be refused");
        assert!(error.contains("does not belong"));
    }

    #[test]
    fn saml_assertion_of_an_in_domain_email_is_accepted() {
        let config = sso_config_for_domain("example.com");
        let email = validate_asserted_email("alice@Example.com", &config)
            .expect("an in-domain asserted email links");
        assert_eq!(email, "alice@Example.com");
    }

    #[test]
    fn opaque_saml_nameid_is_never_usable_as_an_email() {
        let config = sso_config_for_domain("example.com");
        // Opaque NameIDs are external_user_id material: no `@`, no domain.
        for opaque in [
            "_saml_abc123",
            "user@ ",
            "@example.com",
            "a@b",
            "a b@example.com",
        ] {
            assert!(
                validate_asserted_email(opaque, &config).is_err(),
                "'{opaque}' must be refused as an asserted email"
            );
        }
    }

    #[test]
    fn saml_email_attribute_absent_means_refusal_not_nameid_fallback() {
        // The OLD behavior fell back to the raw NameID as the email; the gate
        // exists so the ACS handler refuses instead. An empty/whitespace
        // assertion attribute fails the same syntax bar.
        let config = sso_config_for_domain("example.com");
        assert!(validate_asserted_email("", &config).is_err());
        assert!(validate_asserted_email("   ", &config).is_err());
    }

    #[test]
    fn allowed_domains_mapping_still_admits_partner_domains() {
        let mut config = sso_config_for_domain("example.com");
        config.attribute_mapping = Some(serde_json::json!({
            "allowed_domains": ["partner.example.com"]
        }));
        assert!(validate_asserted_email("bob@partner.example.com", &config).is_ok());
        assert!(validate_asserted_email("bob@evil.example.com", &config).is_err());
    }

    /// Audit F2: a SAML IdP that asserts an email-verification flag must not
    /// assert it false; an absent flag is no claim at all (SAML has no
    /// standardized verified attribute).
    #[test]
    fn asserted_email_verification_flag_only_refuses_when_false() {
        assert!(asserted_email_flag_is_verified(None));
        for verified in ["true", "True", "TRUE", "1", "yes", " yes "] {
            assert!(
                asserted_email_flag_is_verified(Some(verified)),
                "'{verified}' must count as verified"
            );
        }
        for unverified in ["false", "0", "no", "", "   ", "maybe"] {
            assert!(
                !asserted_email_flag_is_verified(Some(unverified)),
                "'{unverified}' must NOT count as verified"
            );
        }
    }
}
