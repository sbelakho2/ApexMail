//! Shared middleware utilities: browser-path classification and the small
//! branded HTML error page the browser-facing middlewares serve instead of
//! a raw JSON dump.

pub mod auth;
pub mod cp_auth;
pub mod ddos;
pub mod idempotency;
pub mod metrics;
pub mod rate_limiter;
pub mod request_logger;
pub mod sales_owner;
pub mod versioning;
pub mod waf;

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

/// Paths whose consumers are human browsers (zero-JS form posts and
/// server-rendered pages) rather than machine API clients:
///
/// - `/web/*` — the SSR form routes (auth, console actions, `/web/admin/*`);
/// - `/consent` — the no-JS cookie-consent endpoint the marketing banner
///   links to;
/// - `/domains/*` and `/campaigns/*` at the root — the data-backed SSR
///   detail pages (the API twins live under `/v1/`);
/// - `/cp` and `/cp/*` — the control-plane page renders.
///
/// API surfaces (`/v1/*`, `/api/*`) never match, so their JSON error
/// contract is untouched.
pub(crate) fn is_browser_facing_path(path: &str) -> bool {
    path.starts_with("/web/")
        || path == "/consent"
        || path.starts_with("/consent/")
        || path == "/domains"
        || path.starts_with("/domains/")
        || path == "/campaigns"
        || path.starts_with("/campaigns/")
        || path == "/cp"
        || path.starts_with("/cp/")
}

/// Small branded HTML error page in the tracking-service template idiom
/// (white card, `#dc2626` accent, mono type, zero radius) — inline-styled,
/// zero-JS, ~15 lines. Every input is a compile-site constant, never user
/// data, so no escaping is required.
///
/// All arguments are static strings; `title` is the document title,
/// `heading` the card heading, `message` the human explanation, and
/// `link_href`/`link_label` the single onward link.
pub(crate) fn browser_error_html(
    title: &str,
    heading: &str,
    message: &str,
    link_href: &str,
    link_label: &str,
) -> String {
    format!(
        "<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>{title} — ApexMail</title>\n\
</head>\n\
<body style=\"margin:0;padding:20px;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#ffffff;font-family:ui-monospace,'JetBrains Mono',monospace;color:#000000\">\n\
<div style=\"background:#ffffff;border:1px solid #e4e4e7;border-top:4px solid #dc2626;border-radius:0;padding:40px;max-width:420px;text-align:center\">\n\
<h1 style=\"font-size:22px;margin:0 0 16px;font-weight:700;color:#dc2626;letter-spacing:-0.01em\">{heading}</h1>\n\
<p style=\"color:#52525b;line-height:1.6;margin:0 0 24px\">{message}</p>\n\
<a href=\"{link_href}\" style=\"display:inline-block;background:#dc2626;color:#ffffff;padding:12px 24px;border-radius:0;text-decoration:none;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;font-size:14px\">{link_label}</a>\n\
</div>\n\
</body>\n\
</html>\n"
    )
}

/// [`browser_error_html`] as a response: `text/html`, explicitly
/// uncacheable (the page is a transient error, never a resource).
pub(crate) fn browser_error_page_response(
    status: StatusCode,
    title: &str,
    heading: &str,
    message: &str,
    link_href: &str,
    link_label: &str,
) -> Response {
    let html = browser_error_html(title, heading, message, link_href, link_label);
    let mut response = (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_paths_match_the_served_surfaces_and_api_paths_do_not() {
        for path in [
            "/web/auth/login",
            "/web/auth/signup",
            "/web/admin/tenants",
            "/web/campaigns/abc/start",
            "/consent",
            "/domains/abc",
            "/campaigns/abc",
            "/cp",
            "/cp/security",
        ] {
            assert!(is_browser_facing_path(path), "{path} must be browser-facing");
        }

        for path in [
            "/v1/auth/login",
            "/v1/domains",
            "/v1/campaigns",
            "/api/auth/session",
            "/api/kcaptcha/challenge",
            "/health",
            "/",
            "/login",
        ] {
            assert!(
                !is_browser_facing_path(path),
                "{path} must stay on the JSON contract"
            );
        }
    }

    #[test]
    fn browser_error_page_is_branded_html_without_a_json_body() {
        let html = browser_error_html(
            "Too Many Requests",
            "Too many attempts",
            "Wait a minute and try again.",
            "/login",
            "Back to sign in",
        );
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("lang=\"en\""));
        assert!(html.contains("<title>Too Many Requests — ApexMail</title>"));
        assert!(html.contains("#dc2626"));
        assert!(html.contains("border-radius:0"));
        assert!(html.contains("href=\"/login\""));
        // No braces at all: the page cannot be mistaken for a JSON error
        // body and no template interpolation can smuggle one in.
        assert!(!html.contains('{'));
    }

    #[test]
    fn browser_error_page_response_sets_html_and_no_store() {
        let response = browser_error_page_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too Many Requests",
            "Too many attempts",
            "Wait a minute and try again.",
            "/login",
            "Back to sign in",
        );
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }
}
