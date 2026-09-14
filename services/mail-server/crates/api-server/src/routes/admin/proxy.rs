//! SSRF-safe proxy endpoint.
//!
//! Invariants:
//! - The destination host must be on `CONTROL_PLANE_PROXY_ALLOWLIST`; an
//!   EMPTY allowlist refuses every request in every environment (a
//!   non-production open relay is still a relay).
//! - The hostname is RESOLVED and every answer checked against the
//!   private/reserved ranges before connecting, and the connection is
//!   PINNED to the validated address — hostname-only checks are DNS-blind,
//!   and re-resolution between check and connect enables DNS rebinding
//!   (same pattern as `crates/devex-service/src/webhook_tester.rs`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(proxy_request).get(proxy_disabled))
}

fn build_proxy_audit_metadata(
    body: &ProxyRequest,
    method: &str,
    host: &str,
    status: u16,
) -> serde_json::Value {
    let forwarded_headers: Vec<String> = body
        .headers
        .as_ref()
        .and_then(|headers| headers.as_object())
        .map(|headers| headers.keys().cloned().collect())
        .unwrap_or_default();

    json!({
        "url": body.url,
        "host": host,
        "method": method,
        "forwardedHeaders": forwarded_headers,
        "hasBody": body.body.is_some(),
        "responseStatus": status,
    })
}

async fn log_proxy_audit(
    state: &AppState,
    auth: &AuthUser,
    host: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        "control_plane.proxy.requested",
        "proxy_request",
        Some(host),
        metadata,
        None,
        None,
    )
    .await;
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRequest {
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: serde_json::Value,
    pub body: serde_json::Value,
}

/// Allowed headers to forward (security allowlist).
///
/// `authorization` and `x-api-key` are intentionally excluded: forwarding
/// client-supplied credentials to an arbitrary upstream host would leak the
/// caller's secrets and could authenticate the proxy request as the caller
/// against the upstream.
const HEADER_ALLOWLIST: &[&str] = &["content-type", "accept", "x-request-id"];

async fn proxy_disabled() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({ "error": "GET not supported on proxy endpoint" })),
    )
}

async fn proxy_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    // Validate URL
    let parsed =
        url::Url::parse(&body.url).map_err(|_| ApiError::Validation(vec!["Invalid URL".into()]))?;

    // Enforce HTTPS in production
    if state.config.environment.is_production() && parsed.scheme() != "https" {
        return Err(ApiError::Validation(vec![
            "Only HTTPS URLs are allowed in production".into(),
        ]));
    }

    // Allowlist gate — an empty allowlist means NO proxying is permitted,
    // in EVERY environment (P1): the previous non-production carve-out made
    // any dev/staging deployment an authenticated open relay.
    let allowlist_str = std::env::var("CONTROL_PLANE_PROXY_ALLOWLIST").unwrap_or_default();
    let allowlist: Vec<&str> = allowlist_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if allowlist.is_empty() {
        return Err(ApiError::Validation(vec![
            "Proxy not configured — set CONTROL_PLANE_PROXY_ALLOWLIST".into(),
        ]));
    }

    let raw_host = parsed.host_str().unwrap_or("");
    // Strip brackets from IPv6 for matching.
    let host_lower = raw_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase();
    if !allowlist
        .iter()
        .any(|allowed| host_lower == *allowed || host_lower.ends_with(&format!(".{allowed}")))
    {
        return Err(ApiError::Validation(vec![
            "URL host not in proxy allowlist".into(),
        ]));
    }

    // SSRF:Block private/RFC1918/link-local/cloud-metadata IPs and hostnames.
    // Blocked hostnames and literal IP addresses.
    let blocked_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "0", "0.0.0.0"];
    // Cloud metadata endpoints.
    let blocked_prefixes = [
        "169.254.",        // AWS/GCP metadata + link-local
        "10.",             // RFC1918
        "192.168.",        // RFC1918
        "fc00:",           // IPv6 ULA
        "fd",              // IPv6 ULA
        "fe80:",           // IPv6 link-local
        "::ffff:127.",     // IPv4-mapped loopback
        "::ffff:10.",      // IPv4-mapped RFC1918
        "::ffff:192.168.", // IPv4-mapped RFC1918
        "::ffff:169.254.", // IPv4-mapped link-local
        "100.64.",         // Carrier-grade NAT (RFC6598)
    ];
    let literal_blocked = blocked_hosts.contains(&host_lower.as_str())
        || blocked_prefixes.iter().any(|p| host_lower.starts_with(p))
// RFC1918 172.16.0.0/12
        || (host_lower.starts_with("172.")
            && host_lower
                .split('.')
                .nth(1)
                .and_then(|s| s.parse::<u8>().ok())
                .is_some_and(|second| (16..=31).contains(&second)))
// Cloud metadata exact IPs
        || host_lower == "169.254.169.254"
        || host_lower == "metadata.google.internal"
// Decimal/octal IP tricks (reject any all-digit hostnames)
        || host_lower.chars().all(|c| c.is_ascii_digit());
    if literal_blocked {
        return Err(ApiError::Validation(vec![
            "Private/internal URLs are not allowed".into(),
        ]));
    }

    // Resolve-then-pin (P1): the checks above are DNS-blind — an allowlisted
    // hostname that RESOLVES to a private/reserved address still reaches the
    // internal network. Resolve off the async runtime, reject when ANY
    // answer is private (the attacker controls which answer the connector
    // picks), and pin the client to the validated address so DNS rebinding
    // cannot swap the target between check and connect.
    let port = parsed.port_or_known_default().unwrap_or(443);
    let resolved: Vec<SocketAddr> = match host_lower.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => resolve_host(&host_lower, port).await.map_err(|e| {
            tracing::warn!(host = %host_lower, error = %e, "proxy host resolution failed");
            ApiError::Validation(vec!["Proxy host could not be resolved".into()])
        })?,
    };
    if let Err(blocked) = first_private_resolved_addr(&host_lower, &resolved) {
        tracing::warn!(host = %host_lower, ip = %blocked, "proxy target resolves to a private IP");
        return Err(ApiError::Validation(vec![
            "Private/internal URLs are not allowed".into(),
        ]));
    }
    let pinned_addr = resolved[0];

    let method = body.method.as_deref().unwrap_or("GET").to_uppercase();
    let host = raw_host.to_string();

    // Build a dedicated client that does NOT follow redirects. The SSRF
    // host/IP allowlist checks only run on the initial URL, so following a
    // 3xx (e.g. to http://169.254.169.254/) would bypass them entirely.
    // `state.http_client` follows up to 10 redirects and is therefore unsafe
    // to use here. `.resolve` pins this host to the SSRF-validated address.
    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host_lower, pinned_addr)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build no-redirect proxy client: {e}");
            ApiError::Internal("proxy client build failed".into())
        })?;

    let mut request = match method.as_str() {
        "GET" => no_redirect_client.get(&body.url),
        "POST" => no_redirect_client.post(&body.url),
        "PUT" => no_redirect_client.put(&body.url),
        "PATCH" => no_redirect_client.patch(&body.url),
        "DELETE" => no_redirect_client.delete(&body.url),
        _ => return Err(ApiError::Validation(vec!["Unsupported HTTP method".into()])),
    };

    // Forward only allowed headers
    if let Some(headers) = &body.headers {
        if let Some(obj) = headers.as_object() {
            for (key, value) in obj {
                if HEADER_ALLOWLIST.contains(&key.to_lowercase().as_str()) {
                    if let Some(val) = value.as_str() {
                        request = request.header(key.as_str(), val);
                    }
                }
            }
        }
    }

    // Forward body for mutation methods
    if let Some(body_data) = &body.body {
        request = request.json(body_data);
    }

    let response = request
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Proxy request failed: {e}");
            ApiError::Internal("Proxy request failed".into())
        })?;

    // Refuse to follow redirects: a 3xx could point at an internal host that
    // was never validated by the SSRF checks above.
    if response.status().is_redirection() {
        return Err(ApiError::BadRequest(
            "upstream returned a redirect; the proxy does not follow redirects".into(),
        ));
    }

    let status = response.status().as_u16();
    log_proxy_audit(
        &state,
        &auth,
        &host,
        build_proxy_audit_metadata(&body, &method, &host, status),
    )
    .await;

    let resp_headers = serde_json::json!({
        "content-type": response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("")
    });

    let resp_body: serde_json::Value = response.json().await.unwrap_or(serde_json::json!(null));

    Ok(Json(ProxyResponse {
        status,
        headers: resp_headers,
        body: resp_body,
    }))
}

// ─── Resolve-then-pin SSRF guard (webhook_tester.rs pattern) ─────────────

/// Resolve `host:port` off the async runtime (std DNS + /etc/hosts) —
/// `to_socket_addrs` is blocking and must not run on a tokio worker.
async fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<_>>())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("DNS resolution task failed: {e}"))?
}

/// Return the first private/reserved address in the answer set, if any.
/// ANY private answer rejects the whole set: the attacker controls which
/// answer the connector picks, so a mixed list is an internal target.
fn first_private_resolved_addr(host: &str, addrs: &[SocketAddr]) -> Result<(), IpAddr> {
    if addrs.is_empty() {
        tracing::warn!(host = %host, "proxy host resolved to no addresses");
        return Err(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    for addr in addrs {
        if is_private_ip(&addr.ip()) {
            return Err(addr.ip());
        }
    }
    Ok(())
}

/// Private/reserved coverage identical to the shared SSRF helper
/// (`mail-common/src/ssrf.rs` family): loopback, RFC1918, link-local
/// (incl. cloud metadata), CGNAT, documentation ranges, broadcast/
/// unspecified, IPv6 ULA/site-local/link-local, and the IPv4 embedded in
/// 6to4/Teredo/IPv4-mapped forms.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let s = ip.segments();
    // Link-local fe80::/10, unique-local fc00::/7, site-local fec0::/10.
    if s[0] & 0xffc0 == 0xfe80 || s[0] & 0xfe00 == 0xfc00 || s[0] & 0xffc0 == 0xfec0 {
        return true;
    }
    // 6to4 (2002::/16) and Teredo (2001:0::/32) embed IPv4 — inspect it.
    if s[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        );
        if is_private_ipv4(&embedded) {
            return true;
        }
    }
    if s[0] == 0x2001 && s[1] == 0x0000 {
        let embedded = Ipv4Addr::new(
            (s[6] >> 8) as u8 ^ 0xff,
            (s[6] & 0xff) as u8 ^ 0xff,
            (s[7] >> 8) as u8 ^ 0xff,
            (s[7] & 0xff) as u8 ^ 0xff,
        );
        if is_private_ipv4(&embedded) {
            return true;
        }
    }
    // IPv4-mapped addresses (the api-server SSRF helper's known gap —
    // covered here).
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&v4);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse::<IpAddr>().expect("test ip parses"), 443)
    }

    #[test]
    fn any_private_answer_rejects_the_whole_resolution() {
        assert!(
            first_private_resolved_addr("mixed.example", &[addr("8.8.8.8"), addr("10.0.0.5")])
                .is_err()
        );
        assert!(first_private_resolved_addr("ok.example", &[addr("8.8.8.8")]).is_ok());
        assert!(
            first_private_resolved_addr("empty.example", &[]).is_err(),
            "no answers must not read as safe"
        );
    }

    #[test]
    fn private_coverage_includes_metadata_and_mapped_forms() {
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
        ] {
            assert!(
                is_private_ip(&blocked.parse::<IpAddr>().unwrap()),
                "{blocked}"
            );
        }
        assert!(!is_private_ip(&"93.184.216.34".parse::<IpAddr>().unwrap()));
        // IPv4-mapped loopback — the exact gap in the shared helper.
        assert!(is_private_ip(
            &"::ffff:127.0.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_ip(&"::1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"fd00::1".parse::<IpAddr>().unwrap()));
    }
}

// ─── Adversarial control-plane proxy tests ─────────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn admin_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: Some("key_adversarial".into()),
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    fn with_allowlist<F: FnOnce() -> R, R>(allowlist: &str, body: F) -> R {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var("CONTROL_PLANE_PROXY_ALLOWLIST").ok();
        std::env::set_var("CONTROL_PLANE_PROXY_ALLOWLIST", allowlist);
        let result = body();
        match previous {
            Some(value) => std::env::set_var("CONTROL_PLANE_PROXY_ALLOWLIST", value),
            None => std::env::remove_var("CONTROL_PLANE_PROXY_ALLOWLIST"),
        }
        result
    }

    #[tokio::test]
    async fn get_is_explicitly_unsupported() {
        let (status, Json(body)) = proxy_disabled().await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(body["error"].as_str().unwrap_or_default().contains("GET"));
    }

    #[tokio::test]
    async fn invalid_urls_are_refused_before_any_network() {
        let Some((state, _pool)) = state_and_pool("adv_proxy_urls").await else {
            return;
        };
        for url in ["not a url", "://missing-scheme", ""] {
            let resp = proxy_request(
                State(state.clone()),
                admin_auth(),
                Json(ProxyRequest {
                    url: url.into(),
                    method: None,
                    headers: None,
                    body: None,
                }),
            )
            .await;
            assert!(
                matches!(resp, Err(ApiError::Validation(_))),
                "{url:?} must be refused, got {resp:?}"
            );
        }
    }

    #[tokio::test]
    async fn empty_allowlist_disables_proxying_entirely() {
        let Some((state, _pool)) = state_and_pool("adv_proxy_allowlist").await else {
            return;
        };
        if std::env::var("CONTROL_PLANE_PROXY_ALLOWLIST").is_ok() {
            eprintln!("skipping: CONTROL_PLANE_PROXY_ALLOWLIST is set in this environment");
            return;
        }
        let resp = proxy_request(
            State(state.clone()),
            admin_auth(),
            Json(ProxyRequest {
                url: "https://example.com/x".into(),
                method: None,
                headers: None,
                body: None,
            }),
        )
        .await;
        assert!(matches!(resp, Err(ApiError::Validation(_))));
    }

    #[tokio::test]
    async fn ssrf_and_allowlist_guards_block_literal_private_targets() {
        let Some((state, _pool)) = state_and_pool("adv_proxy_ssrf").await else {
            return;
        };
        // The allowlist admits the host but the SSRF guard still blocks it.
        for (allowlist, url) in [
            ("127.0.0.1", "http://127.0.0.1:8080/admin"),
            ("localhost", "http://localhost:9000/"),
            ("10.0.0.5", "http://10.0.0.5/"),
            ("192.168.1.10", "http://192.168.1.10/"),
            ("172.16.5.4", "http://172.16.5.4/"),
            (
                "169.254.169.254",
                "http://169.254.169.254/latest/meta-data/",
            ),
            (
                "metadata.google.internal",
                "http://metadata.google.internal/",
            ),
        ] {
            let resp = with_allowlist(allowlist, || {
                futures::executor::block_on(proxy_request(
                    State(state.clone()),
                    admin_auth(),
                    Json(ProxyRequest {
                        url: url.into(),
                        method: None,
                        headers: None,
                        body: None,
                    }),
                ))
            });
            // Either the host is not in the allowlist or the SSRF guard
            // refuses it — never a successful forward to a private target.
            assert!(
                matches!(resp, Err(ApiError::Validation(_))),
                "{url} (allowlist {allowlist}) must be refused, got {resp:?}"
            );
        }
    }

    #[tokio::test]
    async fn unsupported_methods_are_refused_after_ssrf_validation() {
        let Some((state, _pool)) = state_and_pool("adv_proxy_method").await else {
            return;
        };
        // A public literal IP needs no DNS and passes the SSRF guard, so the
        // method check is reached before any socket is opened.
        let resp = with_allowlist("93.184.216.34", || {
            futures::executor::block_on(proxy_request(
                State(state.clone()),
                admin_auth(),
                Json(ProxyRequest {
                    url: "http://93.184.216.34/".into(),
                    method: Some("TRACE".into()),
                    headers: None,
                    body: None,
                }),
            ))
        });
        assert!(matches!(resp, Err(ApiError::Validation(_))));
    }

    #[tokio::test]
    async fn scope_less_callers_are_refused() {
        let Some((state, _pool)) = state_and_pool("adv_proxy_scope").await else {
            return;
        };
        let mut auth = admin_auth();
        auth.scopes = vec![];
        let resp = proxy_request(
            State(state.clone()),
            auth,
            Json(ProxyRequest {
                url: "https://example.com".into(),
                method: None,
                headers: None,
                body: None,
            }),
        )
        .await;
        assert!(matches!(resp, Err(ApiError::Forbidden(_))));
    }

    #[test]
    fn audit_metadata_never_contains_caller_supplied_credentials() {
        let metadata = build_proxy_audit_metadata(
            &ProxyRequest {
                url: "https://example.com/".into(),
                method: Some("POST".into()),
                headers: Some(serde_json::json!({"authorization": "Bearer secret"})),
                body: None,
            },
            "POST",
            "example.com",
            200,
        );
        let text = metadata.to_string();
        assert!(
            !text.to_lowercase().contains("bearer"),
            "credentials must never enter the audit trail: {text}"
        );
        assert_eq!(metadata["method"], "POST");
        assert_eq!(metadata["host"], "example.com");
        assert_eq!(metadata["responseStatus"], 200);
    }
}
