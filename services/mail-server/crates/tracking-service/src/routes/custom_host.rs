//! Custom tracking domain host resolution (capability wave 2).
//!
//! A tenant can point a CNAME from their own host (e.g.
//! `email.example.com`) at the platform tracking host. DNS delivers the
//! request to this service with the CUSTOM host in the `Host` header, so the
//! server must resolve the host back to the owning tenant before it serves
//! click/open/unsubscribe links — and must REFUSE, by name, when the host is
//! not a verified custom tracking domain or when the link inside it belongs
//! to a different workspace. Never a silent bounce to the vendor fallback.
//!
//! Resolution is the explicit `tracking_domains` row (status must be
//! `verified`) joined to the tenant's still-owned parent domain — the same
//! owned-domain authority item 11 uses for redirect destinations. There is
//! deliberately NO cache: deleting a tracking domain stops serving on the
//! very next request, and a deleted row can never be replayed from a stale
//! allow-cache.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use tracing::warn;

use crate::state::AppState;

/// Which authority governs the request's `Host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostScope {
    /// The platform tracking host (or a loopback/test host) — every
    /// authenticated-by-token link is served as before.
    Platform,
    /// A verified custom tracking domain belonging to `tenant_id`.
    Custom { host: String, tenant_id: String },
    /// The host is not a verified custom tracking domain. `unavailable` is
    /// true when the authorization store could not answer (fail closed,
    /// 503) — an outage must never read as "unknown host".
    Unknown {
        host: String,
        reason: &'static str,
        unavailable: bool,
    },
}

/// Extract the request host (lowercase, port and trailing dot stripped).
pub fn request_host(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::HOST)?.to_str().ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // IPv6 literals carry brackets and (possibly) a port: [::1]:8080.
    if let Some(rest) = raw.strip_prefix('[') {
        let host = rest.split(']').next()?;
        return Some(host.trim_end_matches('.').to_ascii_lowercase());
    }
    // A bare IPv6 literal (several colons, no brackets) carries no port.
    if raw.matches(':').count() > 1 {
        return Some(raw.trim_end_matches('.').to_ascii_lowercase());
    }
    let host = raw.split(':').next()?;
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Hosts that always route to the platform itself: the configured tracking
/// base host, the fallback host, and loopback (tests, local development).
fn is_platform_host(state: &AppState, host: &str) -> bool {
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return true;
    }
    let base_host = state
        .config
        .tracking
        .base_url
        .parse::<url::Url>()
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase));
    if base_host.as_deref() == Some(host) {
        return true;
    }
    state
        .config
        .tracking
        .fallback_url
        .parse::<url::Url>()
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .as_deref()
        == Some(host)
}

/// Resolve the request's `Host` to a tenant or a named refusal.
pub async fn resolve_host_scope(state: &AppState, headers: &HeaderMap) -> HostScope {
    let Some(host) = request_host(headers) else {
        // HTTP/1.1 requires Host; an absent one cannot be a custom domain.
        return HostScope::Platform;
    };
    if is_platform_host(state, &host) {
        return HostScope::Platform;
    }
    match lookup_custom_host(state, &host).await {
        Ok(Some(tenant_id)) => HostScope::Custom { host, tenant_id },
        Ok(None) => HostScope::Unknown {
            host,
            reason: "This host is not a verified custom tracking domain for any workspace. \
                     Add it under Domains → Tracking and publish its CNAME record, then verify it.",
            unavailable: false,
        },
        Err(error) => {
            warn!(host = %host, error = %error, "custom tracking host lookup failed — refusing for this request");
            HostScope::Unknown {
                host,
                reason: "The tracking-domain store could not be reached, so this request was \
                         refused rather than guessed. Try again in a moment.",
                unavailable: true,
            }
        }
    }
}

/// The authoritative lookup: a VERIFIED tracking domain whose tenant still
/// owns the parent sending domain (the item-11 owned-domain relation). A
/// missing table (pre-migration deployment) degrades to "no custom hosts".
async fn lookup_custom_host(state: &AppState, host: &str) -> Result<Option<String>, sqlx::Error> {
    let row: Result<Option<(String,)>, sqlx::Error> = sqlx::query_as(
        "SELECT td.tenant_id FROM tracking_domains td \
         JOIN domains d ON d.tenant_id = td.tenant_id AND lower(d.name) = td.parent_domain \
         WHERE td.domain = $1 AND td.status = 'verified' \
         LIMIT 1",
    )
    .bind(host)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(found) => Ok(found.map(|(tenant_id,)| tenant_id)),
        Err(error) if is_missing_store(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn is_missing_store(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .is_some_and(|code| code == "42P01" || code == "42703")
}

/// Refuse a request whose host is not a verified custom tracking domain.
pub fn unknown_host_refusal(host: &str, reason: &str, unavailable: bool) -> Response {
    let status = if unavailable {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    };
    let body = crate::templates::render_tracking_domain_refused_page(host, reason);
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header(
            "content-security-policy",
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; script-src 'none'; style-src 'none'; object-src 'none'",
        )
        .header("x-robots-tag", "noindex, nofollow")
        .header("cache-control", "no-store")
        .body(Body::from(body))
        .unwrap_or_default()
}

/// Refuse a valid token served on a custom host that belongs to ANOTHER
/// workspace — the host's tenant and the link's tenant must be the same.
pub fn tenant_mismatch_refusal(host: &str) -> Response {
    let reason = "The link inside the request belongs to a different workspace than this \
                  tracking domain, so it was refused.";
    let body = crate::templates::render_tracking_domain_refused_page(host, reason);
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "text/html; charset=utf-8")
        .header(
            "content-security-policy",
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; script-src 'none'; style-src 'none'; object-src 'none'",
        )
        .header("x-robots-tag", "noindex, nofollow")
        .header("cache-control", "no-store")
        .body(Body::from(body))
        .unwrap_or_default()
}

/// Gate one decoded token against the host scope. `Ok(())` means serve;
/// `Err(response)` is the honest refusal to return as-is.
#[allow(clippy::result_large_err)] // the refusal IS the axum Response, by contract
pub fn ensure_token_matches_host(scope: &HostScope, token_tenant_id: &str) -> Result<(), Response> {
    match scope {
        HostScope::Platform => Ok(()),
        HostScope::Custom { host, tenant_id } => {
            if tenant_id == token_tenant_id {
                Ok(())
            } else {
                warn!(
                    host = %host,
                    host_tenant = %tenant_id,
                    token_tenant = %token_tenant_id,
                    "tracking link served on a custom host of a different workspace — refused"
                );
                Err(tenant_mismatch_refusal(host))
            }
        }
        HostScope::Unknown {
            host,
            reason,
            unavailable,
        } => Err(unknown_host_refusal(host, reason, *unavailable)),
    }
}

/// Convenience for handlers that extract the scope early: resolve and, when
/// the host itself is unknown/unavailable, return the refusal immediately.
#[allow(clippy::result_large_err)] // the refusal IS the axum Response, by contract
pub async fn host_scope_or_refuse(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<HostScope, Response> {
    let scope = resolve_host_scope(state, headers).await;
    match &scope {
        HostScope::Unknown {
            host,
            reason,
            unavailable,
        } => {
            warn!(host = %host, "tracking request on an unconfigured host — refused");
            Err(unknown_host_refusal(host, reason, *unavailable))
        }
        _ => Ok(scope),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_support;

    #[test]
    fn request_host_normalises_port_case_and_root_dot() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "Track.Customer.Test.:8443".parse().unwrap());
        assert_eq!(
            request_host(&headers).as_deref(),
            Some("track.customer.test")
        );

        let mut headers = HeaderMap::new();
        headers.insert("host", "[::1]:8080".parse().unwrap());
        assert_eq!(request_host(&headers).as_deref(), Some("::1"));

        let mut headers = HeaderMap::new();
        headers.insert("host", "::1".parse().unwrap());
        // A bare (unbracketed) IPv6 literal does not split on ':' — the
        // whole value is the host.
        assert_eq!(request_host(&headers).as_deref(), Some("::1"));

        assert_eq!(request_host(&HeaderMap::new()), None);
    }

    #[tokio::test]
    async fn platform_hosts_and_loopback_are_never_custom_lookups() {
        let state = test_support::offline_state(&[]);
        // The configured base host routes to the platform.
        assert_eq!(
            resolve_host_scope(&state, &host_header("track.test.example")).await,
            HostScope::Platform
        );
        // Loopback (axum_test / local dev) routes to the platform.
        assert_eq!(
            resolve_host_scope(&state, &host_header("localhost")).await,
            HostScope::Platform
        );
        // No Host header at all: platform (HTTP/1.0-style).
        assert_eq!(
            resolve_host_scope(&state, &HeaderMap::new()).await,
            HostScope::Platform
        );
    }

    fn host_header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", value.parse().expect("host header"));
        headers
    }

    /// A store outage must fail CLOSED and say so (503), never read as
    /// "unknown host" 400 with a claim about configuration.
    #[tokio::test]
    async fn store_outage_refuses_as_unavailable() {
        let state = test_support::offline_state(&[]);
        let scope = resolve_host_scope(&state, &host_header("track.customer.test")).await;
        match scope {
            HostScope::Unknown {
                unavailable,
                reason,
                ..
            } => {
                assert!(
                    unavailable,
                    "a dead store is an outage, not a config verdict"
                );
                assert!(reason.contains("could not be reached"), "{reason}");
            }
            other => panic!("expected Unknown(unavailable), got {other:?}"),
        }
    }

    #[test]
    fn token_of_another_tenant_on_a_custom_host_is_refused_by_name() {
        let scope = HostScope::Custom {
            host: "track.customer.test".into(),
            tenant_id: "tenant_a".into(),
        };
        assert!(ensure_token_matches_host(&scope, "tenant_a").is_ok());

        let refusal = ensure_token_matches_host(&scope, "tenant_b")
            .expect_err("a foreign token must be refused");
        assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn unknown_host_refusal_is_named_and_never_a_bounce() {
        let response =
            unknown_host_refusal("track.evil.test", "not a verified tracking domain", false);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert!(
            response.headers().get("location").is_none(),
            "a refusal must never redirect (no silent bounce)"
        );
    }
}
