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

    // Everything past this point operates exclusively on the validated,
    // pinned target — the single seam the SSRF guard guarantees.
    let target = ValidatedProxyTarget {
        url: body.url.clone(),
        host_display: raw_host.to_string(),
        host_lower,
        pinned_addr: resolved[0],
    };
    forward_validated_proxy_request(&state, &auth, target, &body).await
}

/// A proxy target that has passed every SSRF gate: the allowlist, the
/// literal private checks, and resolve-then-pin. Downstream code never
/// re-resolves and never accepts a different host.
struct ValidatedProxyTarget {
    /// The caller's original URL (the pinned client resolves `host_lower`
    /// to `pinned_addr`, so this URL cannot escape the validation).
    url: String,
    /// The host as the caller wrote it — used only for the audit trail.
    host_display: String,
    host_lower: String,
    pinned_addr: SocketAddr,
}

async fn forward_validated_proxy_request(
    state: &AppState,
    auth: &AuthUser,
    target: ValidatedProxyTarget,
    body: &ProxyRequest,
) -> Result<Json<ProxyResponse>, ApiError> {
    let method = body.method.as_deref().unwrap_or("GET").to_uppercase();

    // Build a dedicated client that does NOT follow redirects. The SSRF
    // host/IP allowlist checks only run on the initial URL, so following a
    // 3xx (e.g. to http://169.254.169.254/) would bypass them entirely.
    // `state.http_client` follows up to 10 redirects and is therefore unsafe
    // to use here. `.resolve` pins this host to the SSRF-validated address.
    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&target.host_lower, target.pinned_addr)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build no-redirect proxy client: {e}");
            ApiError::Internal("proxy client build failed".into())
        })?;

    let mut request = match method.as_str() {
        "GET" => no_redirect_client.get(&target.url),
        "POST" => no_redirect_client.post(&target.url),
        "PUT" => no_redirect_client.put(&target.url),
        "PATCH" => no_redirect_client.patch(&target.url),
        "DELETE" => no_redirect_client.delete(&target.url),
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
        state,
        auth,
        &target.host_display,
        build_proxy_audit_metadata(body, &method, &target.host_display, status),
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

// ─── Coverage residuals: the validated pass-through core ─────────

#[cfg(test)]
mod passthrough_tests {
    use super::*;

    fn admin() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some("usr_proxy_cov".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// Serialise tests that mutate the proxy allowlist env var (env access
    /// is process-global; restored on the way out).
    fn with_allowlist_env<F: FnOnce() -> R, R>(allowlist: &str, body: F) -> R {
        static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
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

    /// A state backed by a real canonical pool so the pass-through's
    /// audit write lands in the tamper-evident chain.
    async fn state_with_db(suffix: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::canonical_pool(suffix).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    /// A loopback upstream that observes the forwarded request and can
    /// be told which response to give. Returns (base_addr, observed-URI
    /// receiver). The caller builds the proxy's pinned client against
    /// this address — exactly what `forward_validated_proxy_request`
    /// does once the SSRF guard has produced a `ValidatedProxyTarget`.
    struct MockUpstream {
        addr: SocketAddr,
        observed: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Drop for MockUpstream {
        fn drop(&mut self) {
            // Handles are detached; dropping only stops new spawns.
        }
    }

    async fn start_mock_upstream(mode: &'static str) -> MockUpstream {
        let observed: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed_for_handler = observed.clone();

        async fn handler(
            observed: axum::extract::State<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
            mode: axum::Extension<&'static str>,
            request: axum::extract::Request,
        ) -> axum::response::Response {
            use axum::response::IntoResponse;
            let line = format!("{} {}", request.method(), request.uri());
            let content_type = request
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let x_request_id = request
                .headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let authorization = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                .await
                .unwrap_or_default();
            observed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(format!(
                    "{line}|ct={content_type}|xreq={x_request_id}|auth={authorization}|body={}",
                    String::from_utf8_lossy(&bytes)
                ));
            match mode.0 {
                "redirect" => (
                    axum::http::StatusCode::FOUND,
                    [("location", "http://169.254.169.254/latest")],
                )
                    .into_response(),
                "text" => (
                    axum::http::StatusCode::OK,
                    [("content-type", "text/plain")],
                    "just text".to_string(),
                )
                    .into_response(),
                _ => axum::Json(serde_json::json!({ "echo": "ok" })).into_response(),
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy mock");
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .fallback(handler)
            .layer(axum::Extension(mode))
            .with_state(observed_for_handler);
        let handle = tokio::runtime::Handle::try_current().expect("test runtime");
        handle.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        MockUpstream { addr, observed }
    }

    fn pinned_target(upstream: &MockUpstream, url: String) -> ValidatedProxyTarget {
        ValidatedProxyTarget {
            host_lower: "cov-proxy-mock.internal".into(),
            host_display: "cov-proxy-mock.internal".into(),
            url,
            pinned_addr: upstream.addr,
        }
    }

    fn request_for(upstream: &MockUpstream, path: &str) -> ProxyRequest {
        ProxyRequest {
            url: format!(
                "http://cov-proxy-mock.internal:{}{path}",
                upstream.addr.port()
            ),
            method: None,
            headers: None,
            body: None,
        }
    }

    /// The happy pass-through: every supported method is dispatched, only
    /// allowlisted headers ride along, the JSON body is forwarded, and the
    /// upstream status/headers/body are mapped back. A successful forward
    /// is actor-attributed in the audit chain.
    #[tokio::test]
    async fn pass_through_forwards_methods_headers_bodies_and_maps_back() {
        let Some((state, pool)) = state_with_db("proxy_passthrough").await else {
            return;
        };
        let upstream = start_mock_upstream("json").await;
        let admin = admin();

        // GET (the default method) with an allowlisted and a denied header.
        let body = ProxyRequest {
            url: format!(
                "http://cov-proxy-mock.internal:{}/get?q=1",
                upstream.addr.port()
            ),
            method: None,
            headers: Some(serde_json::json!({
                "X-Request-Id": "req-42",
                "Authorization": "Bearer must-not-forward",
                "Content-Type": "application/json"
            })),
            body: None,
        };
        let target = pinned_target(&upstream, body.url.clone());
        let response = forward_validated_proxy_request(&state, &admin, target, &body)
            .await
            .expect("GET forwards");
        assert_eq!(response.0.status, 200);
        assert_eq!(response.0.headers["content-type"], "application/json");
        assert_eq!(response.0.body["echo"], "ok");

        // Every mutation method reaches the upstream with its body.
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let body = ProxyRequest {
                url: format!(
                    "http://cov-proxy-mock.internal:{}/{}",
                    upstream.addr.port(),
                    method.to_lowercase()
                ),
                method: Some(method.into()),
                headers: None,
                body: Some(serde_json::json!({ "n": 1 })),
            };
            let target = pinned_target(&upstream, body.url.clone());
            let response = forward_validated_proxy_request(&state, &admin, target, &body)
                .await
                .expect("mutation forwards");
            assert_eq!(response.0.status, 200, "{method}");
        }

        let observed = upstream
            .observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(observed.iter().any(|l| l.starts_with("GET /get?q=1")));
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(
                observed
                    .iter()
                    .any(|l| l.starts_with(&format!("{method} /"))),
                "{method} must reach the upstream, got {observed:?}"
            );
        }
        // The allowlisted headers were forwarded; the credential was not.
        let get_line = observed
            .iter()
            .find(|l| l.starts_with("GET /get"))
            .expect("GET observed");
        assert!(get_line.contains("xreq=req-42"), "{get_line}");
        assert!(get_line.contains("auth="), "auth header observed as empty");
        assert!(!get_line.contains("Bearer"), "credentials never forward");
        // The JSON body rode the POST.
        assert!(
            observed
                .iter()
                .any(|l| l.starts_with("POST /") && l.contains(r#""n":1"#)),
            "forwarded body observed, got {observed:?}"
        );

        // The success was audited with the mapped status.
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs WHERE action = 'control_plane.proxy.requested'",
        )
        .fetch_one(&pool)
        .await
        .expect("audit count");
        assert!(audits >= 5, "every forwarded request is audited");
        pool.close().await;
    }

    /// Non-JSON upstream bodies are surfaced as null (never an error) and
    /// 3xx responses are refused outright.
    #[tokio::test]
    async fn pass_through_maps_text_and_refuses_redirects() {
        let Some((state, pool)) = state_with_db("proxy_passthrough_text").await else {
            return;
        };
        let admin = admin();

        let upstream = start_mock_upstream("text").await;
        let body = request_for(&upstream, "/text");
        let target = pinned_target(&upstream, body.url.clone());
        let response = forward_validated_proxy_request(&state.clone(), &admin, target, &body)
            .await
            .expect("text forwards");
        assert_eq!(response.0.status, 200);
        assert_eq!(response.0.headers["content-type"], "text/plain");
        assert_eq!(response.0.body, serde_json::Value::Null);

        let upstream = start_mock_upstream("redirect").await;
        let body = request_for(&upstream, "/bounce");
        let target = pinned_target(&upstream, body.url.clone());
        let refused = forward_validated_proxy_request(&state, &admin, target, &body).await;
        assert!(
            matches!(&refused, Err(ApiError::BadRequest(detail))
                if detail.contains("does not follow redirects")),
            "a redirecting upstream is refused, got {refused:?}"
        );
        pool.close().await;
    }

    /// An unsupported method is a validation error raised before any
    /// socket work, and an unreachable validated address maps to an
    /// honest internal error.
    #[tokio::test]
    async fn pass_through_refuses_bad_methods_and_dead_targets() {
        let Some((state, pool)) = state_with_db("proxy_passthrough_err").await else {
            return;
        };
        let admin = admin();

        // Validation arm: unsupported method never opens a socket.
        let upstream = start_mock_upstream("json").await;
        let mut body = request_for(&upstream, "/trace");
        body.method = Some("trace".into());
        let target = pinned_target(&upstream, body.url.clone());
        let refused = forward_validated_proxy_request(&state.clone(), &admin, target, &body).await;
        assert!(matches!(refused, Err(ApiError::Validation(_))));

        // Send-failure arm: the validated address refuses the connection.
        let mut body = request_for(&upstream, "/dead");
        body.method = None;
        let dead = ValidatedProxyTarget {
            host_lower: "cov-proxy-dead.internal".into(),
            host_display: "cov-proxy-dead.internal".into(),
            url: "http://cov-proxy-dead.internal/x".into(),
            pinned_addr: "127.0.0.1:9".parse().expect("dead socket addr"),
        };
        let failed = forward_validated_proxy_request(&state, &admin, dead, &body).await;
        assert!(
            matches!(failed, Err(ApiError::Internal(_))),
            "an unreachable target is an internal error, got {failed:?}"
        );
        pool.close().await;
    }

    /// Production refuses plaintext proxy targets.
    #[tokio::test]
    async fn production_refuses_plain_http_targets() {
        let Some((state, _pool)) = state_with_db("proxy_production_https").await else {
            return;
        };
        let mut production = crate::app::test_support::test_config();
        production.environment = crate::config::Environment::Production;
        let prod_state =
            crate::app::test_support::test_state_over_with_config(state.db.clone(), production)
                .await;
        let resp = proxy_request(
            State(prod_state),
            admin(),
            Json(ProxyRequest {
                url: "http://example.com/x".into(),
                method: None,
                headers: None,
                body: None,
            }),
        )
        .await;
        assert!(
            matches!(&resp, Err(ApiError::Validation(detail))
                if detail[0].contains("HTTPS")),
            "production must refuse http://, got {resp:?}"
        );
    }

    /// A host outside the allowlist is refused even when the literal-IP
    /// guards would pass it.
    #[tokio::test]
    async fn hosts_outside_the_allowlist_are_refused() {
        let Some((state, _pool)) = state_with_db("proxy_allowlist_miss").await else {
            return;
        };
        let resp = with_allowlist_env("allowed.example", || {
            futures::executor::block_on(proxy_request(
                State(state.clone()),
                admin(),
                Json(ProxyRequest {
                    url: "https://93.184.216.34/".into(),
                    method: None,
                    headers: None,
                    body: None,
                }),
            ))
        });
        assert!(
            matches!(&resp, Err(ApiError::Validation(detail))
                if detail[0].contains("allowlist")),
            "non-allowlisted host refused, got {resp:?}"
        );
    }

    /// The hosts-file resolver seam resolves deterministically, and a
    /// garbage hostname fails without leaving a validation hole.
    #[tokio::test]
    async fn resolve_host_reads_the_hosts_file_and_fails_honestly() {
        let resolved = resolve_host("localhost", 80).await;
        let addrs = resolved.expect("localhost resolves from the hosts file");
        assert!(
            addrs
                .iter()
                .any(|addr| addr.ip().is_loopback() && addr.port() == 80),
            "the loopback answer carries the requested port"
        );
        // An empty hostname cannot resolve — the error side is surfaced.
        assert!(resolve_host("", 443).await.is_err());
    }

    /// 6to4 / Teredo / IPv4-mapped embeddings are inspected, not trusted.
    #[test]
    fn embedded_ipv4_forms_are_inspected() {
        // 6to4 (2002::/16) embedding a loopback address.
        assert!(is_private_ip(&"2002:7f00:1::".parse::<IpAddr>().unwrap()));
        // 6to4 embedding a public address is not private.
        assert!(!is_private_ip(
            &"2002:0808:0808::".parse::<IpAddr>().unwrap()
        ));
        // Teredo (2001:0::/32) embeds the IPv4 XOR-obfuscated: a real
        // loopback (127.0.0.1) is carried as 80ff:fffe in the last segments.
        assert!(is_private_ip(
            &"2001:0000:4136:e378:8000:63bf:80ff:fffe"
                .parse::<IpAddr>()
                .unwrap()
        ));
        // A non-embedded IPv6 stays public.
        assert!(!is_private_ip(
            &"2606:4700::1111".parse::<IpAddr>().unwrap()
        ));
    }

    /// The audit helper writes the actor-attributed row directly.
    #[tokio::test]
    async fn proxy_audit_helper_records_the_row() {
        let Some((state, pool)) = state_with_db("proxy_audit_helper").await else {
            return;
        };
        log_proxy_audit(
            &state,
            &admin(),
            "audited.example",
            build_proxy_audit_metadata(
                &ProxyRequest {
                    url: "https://audited.example/".into(),
                    method: Some("GET".into()),
                    headers: Some(serde_json::json!({"accept": "application/json"})),
                    body: None,
                },
                "GET",
                "audited.example",
                204,
            ),
        )
        .await;
        let row: (String, Option<String>) = sqlx::query_as(
            "SELECT details->>'method', resource_id FROM audit_logs
             WHERE action = 'control_plane.proxy.requested'
               AND resource = 'proxy_request'
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("proxy audit row");
        assert_eq!(row.0, "GET");
        assert_eq!(row.1.as_deref(), Some("audited.example"));
        pool.close().await;
    }
}
